#!/usr/bin/env python2

import socket
from mysqlproxy.util import fsocket
from mysqlproxy.session import Session

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 5595))
s.listen(0)

incoming, (remote_host, remote_port) = s.accept()
fsock = incoming.makefile()

try:
    session = Session(fsock)
except Exception, ex:
    import traceback
    traceback.print_exc()
    fsock.close()
    raise ex
