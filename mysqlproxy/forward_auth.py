"""
overridden pymysql Connection class to allow forward auth.

We don't want the connection to automatically send a handshake
response.  Instead, we want to just grab any auth info and 
forward that to our own client.
"""
from pymysql.connections import _makefile, MysqlPacket, \
        pack_int24, unpack_uint16, \
        unpack_int24, unpack_int32, unpack_int64
from pymysql.util import int2byte, byte2int
from pymysql.err import OperationalError
from pymysql.constants.CLIENT import *
from pymysql.constants.COMMAND import *
from pymysql.charset import charset_by_name
from pymysql._compat import text_type
from functools import partial
from mysqlproxy.client import ProxyConnection
import os
import hashlib
import socket
import struct
import sys
import io

DEBUG = False

class ForwardAuthConnection(ProxyConnection):
    """
    Yanked straight from pymysql
    """
    def _connect(self, **kwargs):
        """
        Filthy shim to stop a full handshake from the actual
        pymysql library so that we can intercept the connection
        and grab the salt.
        """
        sock = None
        try:
            if self.unix_socket and self.host in ('localhost', '127.0.0.1'):
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                t = sock.gettimeout()
                sock.settimeout(self.connect_timeout)
                sock.connect(self.unix_socket)
                sock.settimeout(t)
                self.host_info = "Localhost via UNIX socket"
                if DEBUG: print('connected using unix_socket')
            else:
                sock = socket.create_connection((self.host, self.port), self.connect_timeout)
                self.host_info = "socket %s:%d" % (self.host, self.port)
                if DEBUG: print('connected using socket')
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if self.no_delay:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.socket = sock
            self._rfile = _makefile(sock, 'rb')
            self._get_server_information()

            # we'll be doing this ourselves
            #self._request_authentication()
        except Exception as e:
            self._rfile = None
            if sock is not None:
                try:
                    sock.close()
                except socket.error:
                    pass
            raise OperationalError(
                2003, "Can't connect to MySQL server on %r (%s)" % (self.host, e))

    def forward_authentication(self, auth_response=b'\0'):
        self.forwarded_auth_response = auth_response
        self._request_authentication()

    def _request_authentication(self):
        self.client_flag |= CAPABILITIES
        if self.server_version.startswith('5'):
            self.client_flag |= MULTI_RESULTS

        if self.user is None:
            raise ValueError("Did not specify a username")

        charset_id = charset_by_name(self.charset).id
        if isinstance(self.user, text_type):
            self.user = self.user.encode(self.encoding)

        data_init = struct.pack('<i', self.client_flag) + struct.pack("<I", 1) + \
                     int2byte(charset_id) + int2byte(0)*23

        next_packet = 1

        if self.ssl:
            data = pack_int24(len(data_init)) + int2byte(next_packet) + data_init
            next_packet += 1

            if DEBUG: dump_packet(data)

            self._write_bytes(data)
            self.socket = ssl.wrap_socket(self.socket, keyfile=self.key,
                                          certfile=self.cert,
                                          ssl_version=ssl.PROTOCOL_TLSv1,
                                          cert_reqs=ssl.CERT_REQUIRED,
                                          ca_certs=self.ca)

        data = data_init + self.user + b'\0' + self.forwarded_auth_response

        if self.db:
            if isinstance(self.db, text_type):
                self.db = self.db.encode(self.encoding)
            data += self.db + int2byte(0)

        data = pack_int24(len(data)) + int2byte(next_packet) + data
        next_packet += 2

        if DEBUG: dump_packet(data)

        self._write_bytes(data)

        auth_packet = MysqlPacket(self)
        auth_packet.check_error()
        if DEBUG: auth_packet.dump()

        # if old_passwords is enabled the packet will be 1 byte long and
        # have the octet 254

        if auth_packet.is_eof_packet():
            # send legacy handshake
            #raise NotImplementedError, "old_passwords are not supported. Check to see if mysqld was started with --old-passwords, if old-passwords=1 in a my.cnf file, or if there are some short hashes in your mysql.user table."
            # TODO: is this the correct charset?
            data = _scramble_323(self.password.encode(self.encoding), self.salt.encode(self.encoding)) + b'\0'
            data = pack_int24(len(data)) + int2byte(next_packet) + data

            self._write_bytes(data)
            auth_packet = MysqlPacket(self)
            auth_packet.check_error()
            if DEBUG: auth_packet.dump()

    def post_auth_routine(self):
        """
        Anything that was initialized in a PyMySQL connection
        after a successful authentication
        """
        try:
            if self.sql_mode is not None:
                c = self.cursor()
                c.execute("SET sql_mode=%s", (self.sql_mode,))

            if self.init_command is not None:
                c = self.cursor()
                c.execute(self.init_command)
                self.commit()

            if self.autocommit_mode is not None:
                self.autocommit(self.autocommit_mode)
        except Exception as e:
            self._rfile = None
            if sock is not None:
                try:
                    sock.close()
                except socket.error:
                    pass
            raise OperationalError(
                2003, "Can't connect to MySQL server on %r (%s)" % (self.host, e))
