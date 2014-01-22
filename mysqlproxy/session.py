"""
class responsible for IO and
session state.
"""
from mysqlproxy.packet import ERRPacket

class Session(object):
    def __init__(self, fde):
        self.net_fd = fde
        self.connected = True
        #self.send_initial_handshake()
        #self.get_client_capabilities()
        self.piss_off()

    def piss_off(self):
        err = ERRPacket(0, 1002, "lol no")
        err.write_out(self.net_fd)
        self.disconnect()

    def disconnect(self):
        self.net_fd.close()
        self.connected = False
