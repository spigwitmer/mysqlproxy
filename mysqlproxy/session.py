"""
class responsible for IO and
session state.
"""
from mysqlproxy.packet import OKPacket, ERRPacket, Packet, \
        IncomingPacketChain
from mysqlproxy.types import *
from mysqlproxy import capabilities, cli_commands, status_flags
from random import randint
from mysqlproxy import error_codes as errs
from hashlib import sha1

SERVER_CAPABILITIES = capabilities.PROTOCOL_41 \
        | capabilities.INTERACTIVE \
        | capabilities.SECURE_CONNECTION \
        | capabilities.CONNECT_WITH_DB \
        | capabilities.CONNECT_ATTRS

PERMANENT_STATUS_FLAGS = status_flags.STATUS_AUTOCOMMIT

def generate_nonce(nsize=20):
    return ''.join([chr(randint(1, 255)) for _ in range(0, nsize)])

class HandshakeV10(Packet):
    def __init__(self, server_capabilities, nonce, **kwargs):
        super(HandshakeV10, self).__init__(0, **kwargs)
        # TODO: is server_capabilities even needed?
        server_capabilities = SERVER_CAPABILITIES
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
            ('status_flags', FixedLengthInteger(2, 0)),
            ('cap_flags_upper', FixedLengthInteger(2, (server_capabilities >> 16))),
            ('reserved', FixedLengthInteger(1, 0)),
            ('also_reserved', FixedLengthString(10, '\x00' * 10)),
            ('auth_data_2', FixedLengthString(13, bytes(nonce[8:]) + b'\x00'))
            ]


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
            read_length += auth_resp_len.read_in(pl_fd)
            self.fields.append(('auth_response_len', auth_resp_len))
            auth_response = FixedLengthString(auth_resp_len.val, b'\x00' * auth_resp_len.val)
            if auth_resp_len.val > 0:
                read_length += auth_response.read_in(pl_fd)
        else:
            auth_response = NulTerminatedString(u'')
            read_length += auth_response.read_in(pl_fd)
        self.fields.append(('auth_response', auth_response))
        if client_caps & capabilities.CONNECT_WITH_DB:
            db_name = NulTerminatedString(u'')
            read_length += db_name.read_in(pl_fd)
            self.fields.append(('db_name', db_name))
        if client_caps & capabilities.PLUGIN_AUTH and packet_size - read_length > 0:
            # some asshole clients respond with the PLUGIN_AUTH
            # capability even though we explicitly clear that
            # flag in our own handshake.
            plugin_auth_name = NulTerminatedString(u'')
            read_length += plugin_auth_name.read_in(pl_fd)
            self.fields.append(('plugin_auth_name', plugin_auth_name))
        if client_caps & capabilities.CONNECT_ATTRS:
            client_attrs = KeyValueList({})
            read_length += client_attrs.read_in(pl_fd)
            self.fields.append(('client_attrs', client_attrs))
        return read_length


class HandshakeFailed(Exception):
    pass


class Proxy(object):
    """
    MySQL proxy instance
    This is what actually does brokering between
    client and target db server.
    """
    pass


class Session(object):
    """
    MySQL session wrapper for a file-like.
    This assumes that the given file-like will
    always act as a FIFO (a.k.a. if you're going through UDP,
    do your own packet mangling).
    """
    def __init__(self, fde):
        self.net_fd = fde
        self.connected = True
        self.default_db = None
        self.client_capabilities = 0
        self.server_capabilities = SERVER_CAPABILITIES
        self.server_status = PERMANENT_STATUS_FLAGS
        if self.do_handshake(): # TODO refactor
            self.serve_forever()

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
            if not cli_commands.handle_client_command(self, cmd_packet):
                try:
                    self.net_fd.close()
                except:
                    pass
                self.connected = False
            
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

        if not cap_flags & capabilities.PROTOCOL_41:
            # Forget about it, we will not support the
            # 3.2 protocol
            return False, False, \
                ERRPacket(cap_flags, error_code=1062,
                    error_msg='your client needs MySQL 4.1 protocol support to use mysqlproxy.',
                    seq_id=2
                    )

        #XXX what about LDAP again?
        valid_users = {
            'root': 'l33t',
            'pat': 'lolwut'
            }
        if username not in valid_users:
            return False, cap_flags

        passwd_sha = sha1(valid_users[username]).digest()
        hashed_nonce = sha1(nonce + sha1(passwd_sha).digest()).digest()
        expected_auth_response = \
                ''.join([chr(ord(passwd_sha[x]) ^ ord(hashed_nonce[x])) for x in range(0, 20)])
        return True, expected_auth_response == auth_response, cap_flags

    def do_handshake(self):
        """
        Send handshake, get handshake, something like that
        """
        nonce = generate_nonce()
        handshake_pkt = HandshakeV10(0, nonce, seq_id=0)
        handshake_pkt.write_out(self.net_fd)
        self.net_fd.flush()
        response = HandshakeResponse()
        response.read_in(self.net_fd)
        print 'response seq id: %d' % response.seq_id # it better be 1
        success, authenticated, client_caps = self._init_and_authenticate(nonce, response)
        if success:
            if authenticated:
                resp_pkt = OKPacket(client_caps,
                    affected_rows=0,
                    last_insert_id=0,
                    seq_id=2)
            else:
                resp_pkt = ERRPacket(client_caps,
                    error_code=errs.ACCESS_DENIED,
                    error_msg='LOL NO GOODBYE',
                    seq_id=2)
        else:
            resp_pkt = client_caps
        resp_pkt.write_out(self.net_fd)
        self.net_fd.flush()
        return authenticated
        
    def disconnect(self):
        self.net_fd.close()
        self.connected = False
