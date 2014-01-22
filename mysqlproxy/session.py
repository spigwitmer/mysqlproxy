"""
class responsible for IO and
session state.
"""
from mysqlproxy.packet import OKPacket, ERRPacket, Packet, IncomingPacketChain
from mysqlproxy.types import *
from mysqlproxy import capabilities
from random import randint

def generate_nonce(nsize=20):
    return ''.join([chr(randint(1, 255)) for _ in range(0, nsize)])

class HandshakeV10(Packet):
    def __init__(self, server_capabilities, nonce):
        super(HandshakeV10, self).__init__(0)
        server_capabilities |= capabilities.PLUGIN_AUTH | \
            capabilities.PROTOCOL_41 | \
            capabilities.INTERACTIVE | \
            capabilities.SECURE_CONNECTION | \
            capabilities.CONNECT_WITH_DB
        self.server_capabilities = server_capabilities
        self.nonce = nonce
        # forcing mysql_native_password as auth method
        self.fields = [
            FixedLengthInteger(1, 0x0a),                            # protocol version
            NulTerminatedString(u'5.5.11-mysqlproxy'),              # server version
            FixedLengthInteger(4, 4),                               # connection ID (TODO)
            FixedLengthString(8, bytes(nonce[:8])),                 # auth-data part 1
            FixedLengthInteger(1, 0),                               # filler
            FixedLengthInteger(2, server_capabilities & 0xffff),    # capability flags (lower)
            FixedLengthInteger(1, 0x33),                            # character set (utf-8) TODO
            FixedLengthInteger(2, 0),                               # status flags
            FixedLengthInteger(2, (server_capabilities >> 16)),     #  capability flags (upper)
            FixedLengthInteger(1, 20),                              # length of plugin-auth-data
            FixedLengthString(10, '\x00' * 10),                     # reserved
            FixedLengthString(13, bytes(nonce[8:]) + b'\x00'),      # auth-data part 2
            NulTerminatedString(u'mysql_native_password')           # auth-plugin-name
            ]


class HandshakeResponse(Packet):
    def __init__(self):
        super(HandshakeResponse, self).__init__(0)
        self.fields = [
            FixedLengthInteger(4, 0),                       # capability flags
            FixedLengthInteger(4, 0),                       # max packet size
            FixedLengthInteger(1, 0),                       # character set
            FixedLengthString(23, '\x00' * 23),             # reserved
            NulTerminatedString(u''),                       # username
            FixedLengthInteger(1, 0),                       # auth response length
            ]

    def read_in(self, net_fd):
        """
        Read in variable size auth response, followed by dbase + auth plugin name
        """
        """
        Generic read-in of all fields
        """
        ipc = IncomingPacketChain()
        ipc.read_in(net_fd)
        read_length = 0
        for field in self.fields:
            read_length += field.read_in(ipc.payload)
        auth_response_len = self.fields[-1].val
        auth_response = FixedLengthString(auth_response_len, b'\x00' * auth_response_len)
        if auth_response_len > 0:
            read_length += auth_response.read_in(ipc.payload)
        self.fields.append(auth_response)
        plugin_auth_name = NulTerminatedString(u'')
        read_length += plugin_auth_name.read_in(ipc.payload)
        self.fields.append(plugin_auth_name)
        return read_length


class Session(object):
    def __init__(self, fde):
        self.net_fd = fde
        self.connected = True
        self.resolve_handshake()
        self.disconnect()

    def authenticate(self, nonce, response):
        cap_flags = response.fields[0].val
        return False, cap_flags

    def resolve_handshake(self):
        nonce = generate_nonce()
        handshake_pkt = HandshakeV10(0, nonce)
        handshake_pkt.write_out(self.net_fd)
        self.net_fd.flush()
        print 'wrote out server handshake'
        response = HandshakeResponse()
        response.read_in(self.net_fd)
        print 'got client response'
        authenticated, client_caps = self.authenticate(nonce, response)
        if authenticated:
            resp_pkt = OKPacket(client_caps, affected_rows=0, last_insert_id=0, seq_id=2)
        else:
            resp_pkt = ERRPacket(client_caps, error_code=6969, error_msg='Could not authenticate', seq_id=2)
        import pdb; pdb.set_trace()
        resp_pkt.write_out(self.net_fd)
        self.net_fd.flush()
        return authenticated
        
    def disconnect(self):
        self.net_fd.close()
        self.connected = False
