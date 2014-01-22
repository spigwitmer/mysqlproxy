"""
Stupidity
"""
class fsocket(object):
    """
    Turn inet stream socket into file-like
    """
    def __init__(self, sock):
        self.sock = sock

    def write(self, data):
        data_len = len(data)
        written = 0
        while written < data_len:
            written += self.sock.send(data[written:])
        return written

    def read(self, nbytes=0):
        read_in = 0
        data_buf = b''
        if nbytes == 0:
            data_buf = self.sock.recv()
            if len(data_buf) == 0:
                raise Exception('Connection closed')

        while read_in < nbytes:
            new_buf = self.sock.recv(nbytes - read_in)
            read_in = len(new_buf)
            if read_in == 0:
                raise Exception('Connection closed')
            data_buf += new_buf
        return data_buf
