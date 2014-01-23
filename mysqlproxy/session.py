"""
class responsible for IO and
session state.
"""
from mysqlproxy.packet import OKPacket, ERRPacket, Packet, IncomingPacketChain
from mysqlproxy.types import *
from mysqlproxy import capabilities
from random import randint
from mysqlproxy import error_codes as errs

def generate_nonce(nsize=20):
    return ''.join([chr(randint(1, 255)) for _ in range(0, nsize)])

class HandshakeV10(Packet):
    def __init__(self, server_capabilities, nonce):
        super(HandshakeV10, self).__init__(0)
        server_capabilities |= capabilities.PROTOCOL_41 | \
            capabilities.INTERACTIVE | \
            capabilities.SECURE_CONNECTION | \
            capabilities.CONNECT_WITH_DB
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
        self.fields = [
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
        client_caps = self.fields[0].val
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
            print 'client selecting db: %s' % db_name.val
        if client_caps & capabilities.PLUGIN_AUTH:
            plugin_auth_name = NulTerminatedString(u'')
            read_length += plugin_auth_name.read_in(pl_fd)
            self.fields.append(('plugin_auth_name', plugin_auth_name))
            print 'client using PLUGIN_AUTH (%s), why the fuck is the client asking for this' % plugin_auth_name.val
        if client_caps & capabilities.CONNECT_ATTRS:
            client_attrs = KeyValueList({})
            read_length += client_attrs.read_in(pl_fd)
            self.fields.append(('client_attrs', client_attrs))
            print 'client sent connect attrs: %s' % client_attrs.val
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
