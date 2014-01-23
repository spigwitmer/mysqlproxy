"""
class responsible for IO and
session state.
"""
from mysqlproxy.packet import OKPacket, ERRPacket, Packet, \
        IncomingPacketChain, OutgoingPacketChain
from mysqlproxy.types import *
from mysqlproxy import capabilities, cli_commands
from random import randint
from mysqlproxy import error_codes as errs
from hashlib import sha1

SERVER_CAPABILITIES = capabilities.PROTOCOL_41 \
        | capabilities.INTERACTIVE \
        | capabilities.SECURE_CONNECTION \
        | capabilities.CONNECT_WITH_DB \
        | capabilities.CONNECT_ATTRS

def generate_nonce(nsize=20):
    return ''.join([chr(randint(1, 255)) for _ in range(0, nsize)])

class HandshakeV10(Packet):
    def __init__(self, server_capabilities, nonce):
        super(HandshakeV10, self).__init__(0)
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
            ('charset', FixedLengthInteger(1, 0x33)),
            ('status_flags', FixedLengthInteger(2, 0)),
            ('cap_flags_upper', FixedLengthInteger(2, (server_capabilities >> 16))),
            ('reserved', FixedLengthInteger(1, 0)),
            ('also_reserved', FixedLengthString(10, '\x00' * 10)),
            ('auth_data_2', FixedLengthString(13, bytes(nonce[8:]) + b'\x00'))
            ]


class HandshakeResponse(Packet):
    def __init__(self):
        super(HandshakeResponse, self).__init__(0)
        self.fields = [ # these 5 fields will be in the payload regardless
            ('client_capabilities', FixedLengthInteger(4, 0)),
            ('max_packet_size', FixedLengthInteger(4, 0)),
            ('charset', FixedLengthInteger(1, 0)),
            ('reserved', FixedLengthString(23, '\x00' * 23)),
            ('username', NulTerminatedString(u''))
            ]

    def read_in_internal(self, pl_fd):
        """
        Read in variable size auth response, followed by dbase + auth plugin name
        """
        read_length = super(HandshakeResponse, self).read_in_internal(pl_fd)
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
        if client_caps & capabilities.PLUGIN_AUTH:
            # LOL
            plugin_auth_name = NulTerminatedString(u'')
            read_length += plugin_auth_name.read_in(pl_fd)
            self.fields.append(('plugin_auth_name', plugin_auth_name))
            # we told the client we don't support PLUGIN_AUTH but it sends it to us anyway
            print 'client seriously using PLUGIN_AUTH (%s) why the fuck is the client sending this?' % plugin_auth_name.val
        if client_caps & capabilities.CONNECT_ATTRS:
            client_attrs = KeyValueList({})
            read_length += client_attrs.read_in(pl_fd)
            self.fields.append(('client_attrs', client_attrs))
        return read_length


class Session(object):
    def __init__(self, fde):
        self.net_fd = fde
        self.connected = True
        self.default_db = None
        self.client_capabilities = 0
        self.server_capabilities = SERVER_CAPABILITIES
        if self.do_handshake():
            self.serve_forever()


    def send_payload(self, what):
        opc = OutgoingPacketChain()
        if type(what) == list:
            for field in what:
                opc.add_field(what)
        else:
            opc.add_field(what)
        return opc.write_out(self.net_fd)

    def serve_forever(self):
        """
        Client command loop
        """
        while self.connected:
            cmd_packet = self.get_next_client_command()
            

    def get_next_client_command(self):
        """
        Read next packet in.  This should only
        be called after a successful handshake
        with the client.
        """
        ipc = IncomingPacketChain()
        ipc.read_in(self.net_fd)
        return ipc.payload.read()

    def init_and_authenticate(self, nonce, response):
        cap_flags = response.get_field('client_capabilities').val
        self.client_capabilities = cap_flags
        username = response.get_field('username').val
        auth_response = response.get_field('auth_response').val

        #XXX something about LDAP?
        valid_users = {
            'root': 'l33t',
            'pat': 'lolwut'
            }
        if username not in valid_users:
            return False, cap_flags

        passwd_sha = sha1(valid_users[username]).digest()
        hashed_nonce = sha1(nonce + sha1(passwd_sha).digest()).digest()
        expected_auth_response = ''.join([chr(ord(passwd_sha[x]) ^ ord(hashed_nonce[x])) for x in range(0, 20)])
        return expected_auth_response == auth_response, cap_flags

    def do_handshake(self):
        nonce = generate_nonce()
        handshake_pkt = HandshakeV10(0, nonce)
        handshake_pkt.write_out(self.net_fd)
        self.net_fd.flush()
        response = HandshakeResponse()
        response.read_in(self.net_fd)
        authenticated, client_caps = self.init_and_authenticate(nonce, response)
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
        resp_pkt.write_out(self.net_fd)
        self.net_fd.flush()
        return authenticated
        
    def disconnect(self):
        self.net_fd.close()
        self.connected = False
