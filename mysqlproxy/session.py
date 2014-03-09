"""
classes responsible for IO and
session state.
"""
from mysqlproxy.packet import OKPacket, ERRPacket, Packet, \
        IncomingPacketChain
from mysqlproxy.types import *
from mysqlproxy import capabilities, cli_commands, status_flags
from mysqlproxy.query_response import ResultSetText
from mysqlproxy import column_types, error_codes as errs
from mysqlproxy.plugin import PluginRegistry
from mysqlproxy.forward_auth import ForwardAuthConnection
from mysqlproxy.client import ProxyConnection
from mysqlproxy.charset import CHARSETS_BY_NAME
from random import randint
from hashlib import sha1
import pymysql
from pymysql.err import ProgrammingError, \
        OperationalError, InternalError
import logging
import traceback

_LOG = logging.getLogger(__name__)

# stuff that we will flat out not support no matter what
# the target host reports in its capabilities
SERVER_INCAPABILITIES = capabilities.COMPRESS \
    | capabilities.SSL \
    | capabilities.PLUGIN_AUTH

# stuff that we will always support transparently
PERMANENT_SERVER_CAPABILITIES = capabilities.PROTOCOL_41 \
    | capabilities.SECURE_CONNECTION \

PERMANENT_STATUS_FLAGS = status_flags.STATUS_AUTOCOMMIT


def generate_nonce(nsize=20):
    return ''.join([chr(randint(1, 255)) for _ in range(0, nsize)])


class HandshakeV10(Packet):
    def __init__(self, server_capabilities, nonce, status_flags, **kwargs):
        super(HandshakeV10, self).__init__(0, **kwargs)
        self.server_capabilities = server_capabilities
        self.nonce = nonce
        # forcing mysql_native_password as auth method
        self.fields = [
            ('protocol_version', FixedLengthInteger(1, 0x0a)),
            ('server_version', NulTerminatedString(u'5.5.11-mysqlproxy')),
            ('connection_id', FixedLengthInteger(4, 4)),
            ('auth_data_1', FixedLengthString(8, bytes(nonce[:8]))),
            ('filler', FixedLengthInteger(1, 0)),
            ('cap_flags_lower', FixedLengthInteger(2, server_capabilities & 0xffff)),
            ('charset', FixedLengthInteger(1, 0x21)),
            ('status_flags', FixedLengthInteger(2, status_flags)),
            ('cap_flags_upper', FixedLengthInteger(2, (server_capabilities >> 16))),
            ]

        if server_capabilities & capabilities.PLUGIN_AUTH:
            self.fields.append(('auth_plugin_data_len', FixedLengthInteger(1, 21)))
        else:
            self.fields.append(('reserved', FixedLengthInteger(1, 0)))

        self.fields += [
            ('also_reserved', FixedLengthString(10, '\x00' * 10)),
            ('auth_data_2', FixedLengthString(13, bytes(nonce[8:]) + b'\x00')),
            ]
        if server_capabilities & capabilities.PLUGIN_AUTH:
            self.fields.append(('auth_plugin_name', 
                NulTerminatedString(u'mysql_native_password')))


class HandshakeResponse(Packet):
    def __init__(self, **kwargs):
        super(HandshakeResponse, self).__init__(0, **kwargs)
        self.fields = [ # these 5 fields will be in the payload regardless
            ('client_capabilities', FixedLengthInteger(4, 0)),
            ('max_packet_size', FixedLengthInteger(4, 0)),
            ('charset', FixedLengthInteger(1, 0)),
            ('reserved', FixedLengthString(23, '\x00' * 23)),
            ('username', NulTerminatedString(u''))
            ]

    def read_in_internal(self, pl_fd, packet_size):
        """
        Read in variable size auth response, followed by dbase + auth plugin name
        """
        read_length = super(HandshakeResponse, self).read_in_internal(pl_fd, packet_size)
        client_caps = self.get_field('client_capabilities').val
        if client_caps & capabilities.SECURE_CONNECTION:
            auth_resp_len = FixedLengthInteger(1, 0)
            read_length += auth_resp_len.read_in(pl_fd, label='auth_resp_len')
            self.fields.append(('auth_response_len', auth_resp_len))
            auth_response = FixedLengthString(auth_resp_len.val, b'\x00' * auth_resp_len.val)
            if auth_resp_len.val > 0:
                read_length += auth_response.read_in(pl_fd, label='auth_response')
        else:
            auth_response = NulTerminatedString(u'')
            read_length += auth_response.read_in(pl_fd, label='auth_response')
        self.fields.append(('auth_response', auth_response))
        if client_caps & capabilities.CONNECT_WITH_DB:
            db_name = NulTerminatedString(u'')
            read_length += db_name.read_in(pl_fd, label='db_name')
            self.fields.append(('db_name', db_name))
        if client_caps & capabilities.PLUGIN_AUTH and packet_size - read_length > 0:
            plugin_auth_name = NulTerminatedString(u'')
            read_length += plugin_auth_name.read_in(pl_fd, 'plugin_auth_name')
            self.fields.append(('plugin_auth_name', plugin_auth_name))
        if client_caps & capabilities.CONNECT_ATTRS:
            client_attrs = KeyValueList({})
            read_length += client_attrs.read_in(pl_fd, label='client_attrs')
            self.fields.append(('client_attrs', client_attrs))
        return read_length


class HandshakeFailed(Exception):
    pass


class AuthenticationFailed(Exception):
    pass


class SQLProxy(object):
    """
    MySQL proxy instance
    This is what actually does brokering between
    client and target db server.
    """
    def __init__(self, client_fd, host=u'127.0.0.1', port=3306, user=u'root', passwd=u'', **kwargs):
        self.client_fd = client_fd
        self.host = host
        self.port = port
        self.user = user
        self.passwd = passwd
        self.charset_id = 0
        unix_socket = kwargs.pop('socket', None)
        self.forward_auth = kwargs.pop('forward_auth', False)
        if self.forward_auth:
            connection_class = ForwardAuthConnection
        else:
            connection_class = ProxyConnection
        if unix_socket:
            self.client_conn = connection_class(unix_socket=unix_socket, user=user, passwd=passwd)
        else:
            self.client_conn = connection_class(self.host, port=port, user=user, passwd=passwd)
        if not self.forward_auth:
            # static user:passwd combo to access the proxy
            self.client_user = kwargs['client_user']
            self.client_passwd = kwargs['client_passwd']
        self.session = Session(client_fd, self, 
            (self.client_conn.server_capabilities | PERMANENT_SERVER_CAPABILITIES) \
                & (0xffffffff ^ SERVER_INCAPABILITIES))
        self.plugins = PluginRegistry()

    def change_db(self, dbname):
        """
        Changes default database
        Returns OK or ERR
        """
        try:
            self.client_conn.select_db(dbname)
            return OKPacket(self.session.client_capabilities,
                0, 0, seq_id=1)
        except (OperationalError, InternalError) as ex:
            err_code, err_msg = ex
            return ERRPacket(self.session.client_capabilities,
                error_code=err_code, error_msg=err_msg, seq_id=1)

    def start(self):
        try:
            if self.session.do_handshake():
                self.charset_id = \
                    CHARSETS_BY_NAME[self.client_conn.character_set_name()][0]
                self.session.serve_forever()
        finally:
            self.client_conn.close()

    def build_response_from_query(self, query):
        """
        Do the actual query on the target MySQL host.
        Returns a packet type of either OK, ERR, or a ResultSetText
        """
        cursor = self.client_conn.cursor()
        num_rows = cursor.execute(query)
        results = cursor.fetchall()
        if not results or len(results) == 0:
            cursor.close()
            return OKPacket(self.session.client_capabilities,
                affected_rows=num_rows,
                last_insert_id=cursor.lastrowid,
                seq_id=1
                )
        col_types = cursor.description
        cursor.close()
        response = ResultSetText(self.session.client_capabilities,
            flags=self.session.server_status)
        for colname, coltype, col_max_len, \
                field_len, field_max_len, _, _ in col_types:
            response.add_column(unicode(colname), coltype, field_len)
        for row in results:
            lvals = list(row)
            response.add_row(lvals)
        return response


class Session(object):
    """
    MySQL session wrapper for a file-like.
    This assumes that the given file-like will
    always act as a FIFO (a.k.a. if you're going through UDP,
    do your own packet mangling).
    """
    def __init__(self, fde, proxy_obj, server_capabilities):
        self.net_fd = fde
        self.connected = True
        self.charset_id = 0
        self.default_db = None
        self.client_capabilities = 0
        self.server_capabilities = server_capabilities
        self.server_status = PERMANENT_STATUS_FLAGS
        self.proxy_obj = proxy_obj

    def send_payload(self, what):
        """
        Write out given packets and flush socket
        `what` may be a single packet of list of packets
        """
        nbytes = 0
        last_seq_id = 0
        if type(what) == list:
            for field in what:
                more_bytes, last_seq_id = field.write_out(self.net_fd)
                nbytes += more_bytes
        else:
            more_bytes, last_seq_id = what.write_out(self.net_fd)
            nbytes += more_bytes
        self.net_fd.flush()
        return (nbytes, last_seq_id)

    def serve_forever(self):
        """
        Client command loop
        """
        while self.connected:
            cmd_packet = self.get_next_client_command()
            try:
                if not cli_commands.handle_client_command(self, cmd_packet):
                    try:
                        self.net_fd.close()
                    except:
                        pass
                    self.connected = False
            except (InternalError, OperationalError, 
                    ProgrammingError) as ex:
                traceback.print_exc()
                self.send_payload(ERRPacket(self.client_capabilities,
                    9999, u'Error occured during operation: %s' % ex,
                    seq_id=1))
            
    def get_next_client_command(self):
        """
        Read next packet in.  This should only
        be called after a successful handshake
        with the client.
        """
        ipc = IncomingPacketChain()
        ipc.read_in(self.net_fd)
        return ipc.payload.read()

    def _init_and_authenticate(self, nonce, response):
        """
        Store client capabilities and do auth stuff
        """
        cap_flags = response.get_field('client_capabilities').val
        self.client_capabilities = cap_flags
        username = response.get_field('username').val
        auth_response = response.get_field('auth_response').val
        self.charset_id = response.get_field('charset').val

        if self.proxy_obj.forward_auth:
            if not auth_response:
                auth_response = b'\0' # empty password
            self.proxy_obj.client_conn.user = username
            self.proxy_obj.client_conn.forward_authentication(auth_response)
            self.proxy_obj.client_conn.post_auth_routine()
            return True, True, cap_flags

        if not cap_flags & capabilities.PROTOCOL_41:
            return False, False, \
                ERRPacket(cap_flags, error_code=1062,
                    error_msg='your client needs MySQL 4.1 protocol support to use mysqlproxy.',
                    seq_id=2
                    )

        plugin_continue, ret_val = self.proxy_obj.plugins.call_hooks('auth',
            self, response, username)
        if not plugin_continue:
            return True, ret_val, cap_flags

        try:
            if response.get_field('plugin_auth_name').val != 'mysql_native_password':
                return False, False, ERRPacket(cap_flags,
                    error_code=errs.ACCESS_DENIED,
                    error_msg='I only speak mysql_native_passwd for auth!',
                    seq_id=2)
        except:
            pass

        valid_users = {
            self.proxy_obj.client_user: self.proxy_obj.client_passwd
            }
        if username not in valid_users:
            return True, False, cap_flags

        if auth_response:
            passwd_sha = sha1(valid_users[username]).digest()
            hashed_nonce = sha1(nonce + sha1(passwd_sha).digest()).digest()
            expected_auth_response = \
                    ''.join([chr(ord(passwd_sha[x]) ^ ord(hashed_nonce[x])) for x in range(0, 20)])
        else:
            # username with no password
            if valid_users[username] in (None, ''):
                expected_auth_response = auth_response
            else:
                return True, False, cap_flags
        return True, expected_auth_response == auth_response, cap_flags

    def do_handshake(self):
        """
        Send handshake, get handshake, something like that
        """
        last_seq_id = 0
        try:
            if self.proxy_obj.forward_auth:
                nonce = self.proxy_obj.client_conn.salt
            else:
                nonce = generate_nonce()
            handshake_pkt = HandshakeV10(self.server_capabilities | PERMANENT_SERVER_CAPABILITIES, nonce,
                self.server_status, seq_id=0)
            handshake_pkt.write_out(self.net_fd)
            last_seq_id += 2
            self.net_fd.flush()
            response = HandshakeResponse()
            # TODO: SSL / Compression
            response.read_in(self.net_fd)
            _LOG.debug('response seq id: %d' % response.seq_id) # it better be 1
            success, authenticated, client_caps = self._init_and_authenticate(nonce, response)
            if success:
                if authenticated:
                    try:
                        db_name = response.get_field('db_name').val
                        self.proxy_obj.client_conn.select_db(db_name)
                    except ValueError:
                        pass
                    self.proxy_obj.client_conn.set_charset('utf8')
                    resp_pkt = OKPacket(client_caps,
                        affected_rows=0,
                        last_insert_id=0,
                        status_flags=self.server_status,
                        seq_id=2)
                else:
                    resp_pkt = ERRPacket(client_caps,
                        error_code=errs.ACCESS_DENIED,
                        error_msg='Access denied',
                        seq_id=2)
            else:
                resp_pkt = client_caps
            resp_pkt.write_out(self.net_fd)
            self.net_fd.flush()
            return authenticated
        except Exception as ex:
            traceback.print_exc()
            ERRPacket(0, 9999, 'Internal Server Error: %s' % ex,
                seq_id=last_seq_id).write_out(self.net_fd)
            return False
        
    def disconnect(self):
        self.net_fd.close()
        self.connected = False
