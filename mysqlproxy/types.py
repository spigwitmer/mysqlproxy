"""
Protocol wire types
"""
import struct
from StringIO import StringIO
import logging

_LOG = logging.getLogger(__name__)

__all__ = [
    'MySQLDataType',
    'FixedLengthString',
    'RestOfPacketString',
    'LengthEncodedString',
    'NulTerminatedString',
    'FixedLengthInteger',
    'LengthEncodedInteger',
    'KeyValueList'
    ]

def fixed_length_byte_val(size, inbytes):
    """
    Integer value of fixed length integer with size 
    `size` from raw bytes `inbytes`
    """
    inbytes = [b for b in inbytes]
    val = 0
    for i in range(0, size):
        val += ord(inbytes[i]) * (256 ** i)
    return val


class MySQLDataType(object):
    """
    Generic for a data type found in a payload
    """
    def __init__(self):
        self.val = b''
        self.length = 0
        self._old_read_in = self.read_in
        def debug_read_in(fstream, label="<unlabeled>"):
            ret = self._old_read_in(fstream)
            if label:
                print_val = self.val
                if type(print_val) in [unicode,str,bytes]:
                    print_val = repr(print_val)
                _LOG.debug('%s\t\t%s\t\t<--\t\t%s (%d)' % (self.__class__, label, print_val, ret))
            return ret
        self.read_in = debug_read_in

        self._old_write_out = self.write_out
        def debug_write_out(fstream, label="<unlabeled>"):
            ret = self._old_write_out(fstream)
            if label:
                print_val = self.val
                if type(print_val) in [unicode,str,bytes]:
                    print_val = repr(print_val)
                _LOG.debug('%s\t\t%s\t\t-->\t\t%s (%d)' % (self.__class__, label, print_val, ret))
            return ret
        self.write_out = debug_write_out

    def read_in(self, fstream):
        """
        Read data in from stream
        """
        raise NotImplementedError

    def write_out(self, fstream):
        """
        Write relevant data to stream
        """
        raise NotImplementedError


class FixedLengthString(MySQLDataType):
    """
    String of a static length
    """
    def __init__(self, size, val = None):
        super(FixedLengthString, self).__init__()
        self.val = None
        self.length = size
        if val:
            if len(val) != size:
                raise ValueError('lolwut')
            self.val = val

    def read_in(self, fstream):
        self.val = fstream.read(self.length)
        return self.length

    def write_out(self, fstream):
        fstream.write(bytes(self.val))
        return self.length


class RestOfPacketString(MySQLDataType):
    """
    AKA the EOF string
    """
    def __init__(self, val):
        super(RestOfPacketString, self).__init__()
        self.val = bytes(val)
        self.length = len(self.val)

    def read_in(self, fde):
        """
        EOF strings read the rest of the packet
        """
        self.val = bytes(fde.read())
        self.length = len(self.val)
        return self.length

    def write_out(self, fde):
        """
        Write out
        """
        fde.write(bytes(self.val))
        return len(bytes(self.val))


class NulTerminatedString(MySQLDataType):
    """
    Null-terminated C-style string
    """
    def __init__(self, val=None):
        super(NulTerminatedString, self).__init__()
        if val != None and type(val) != unicode:
            raise ValueError('NulTerminatedString initial val must be unicode')
        self.val = val
        self.length = len(val) + 1

    def read_in(self, fstream):
        self.length = 1
        self.val = b''
        onebyte = bytes(fstream.read(1))
        while onebyte != b'\x00':
            self.val += onebyte
            self.length += 1
            onebyte = bytes(fstream.read(1))
        return self.length

    def write_out(self, fstream):
        fstream.write(bytes(self.val) + '\x00')
        return self.length


class LengthEncodedString(MySQLDataType):
    def __init__(self, val=u''):
        super(LengthEncodedString, self).__init__()
        self.val = val
        self.length = LengthEncodedInteger(len(val)).length + len(val)

    def read_in(self, net_fd):
        str_length = LengthEncodedInteger(0)
        total_read = str_length.read_in(net_fd, label=None)
        if str_length.val > 0:
            actual_str = FixedLengthString(str_length.val, u'')
            total_read += actual_str.read_in(net_fd, label=None)
            self.val = actual_str.val
        else:
            self.val = u''
        self.length = total_read
        return total_read

    def write_out(self, net_fd):
        total_written = LengthEncodedInteger(len(self.val)).write_out(net_fd, label=None)
        if len(self.val) > 0:
            total_written += FixedLengthString(len(self.val), self.val).write_out(net_fd, label=None)
        return total_written


class FixedLengthInteger(MySQLDataType):
    """
    Integer of static size
    """
    def __init__(self, size, val=0):
        super(FixedLengthInteger, self).__init__()
        self.length = size
        self.val = val

    def read_in(self, fstream):
        bytes_read = fstream.read(self.length)
        if len(bytes_read) != self.length:
            raise ValueError('Expected %d bytes, got %d' % (self.length, len(bytes_read)))
        self.val = fixed_length_byte_val(self.length, bytes_read)
        return self.length

    def write_out(self, fstream=None):
        val = self.val
        mbytes = b''
        for _ in range(0, self.length):
            mbytes += bytes(chr(val & 255))
            val >>= 8
        if fstream:
            fstream.write(mbytes)
            return len(mbytes)
        else:
            return mbytes


class LengthEncodedInteger(MySQLDataType):
    """
    Integer with the length given
    """
    def __init__(self, val):
        super(LengthEncodedInteger, self).__init__()
        self.val = val
        if val:
            # stupidly calculate length
            sio = StringIO()
            self.write_out(sio, label=None)
            self.length = sio.len
        else:
            self.length = 0

    def read_in(self, fstream):
        sentinel = ord(fstream.read(1))
        read_amt = 0
        if sentinel < 0xfb:
            self.val = sentinel
            read_amt = 1
        elif sentinel == 0xfc:
            self.val, = struct.unpack('<H', fstream.read(2))
            read_amt = 3
        elif sentinel == 0xfd:
            self.val, = struct.unpack('<L', fstream.read(3) + '\x00')
            read_amt = 4
        elif sentinel == 0xfe:
            self.val, = struct.unpack('<L', fstream.read(4))
            read_amt = 5
        self.length = read_amt
        return read_amt

    def write_out(self, fstream):
        write_buf = b''
        if self.val < 251:
            write_buf += bytes(chr(self.val))
        elif self.val >= 251 and self.val < 2**16:
            write_buf += bytes(chr(0xfc) + struct.pack('<H', self.val))
        elif self.val >= 2**16 and self.val < 2**24:
            write_buf += bytes(chr(0xfd) + struct.pack('<L', self.val)[:3])
        elif self.val >= 2**24 and self.val < 2**64:
            write_buf += bytes(chr(0xfe) + struct.pack('<Q', self.val))
        fstream.write(write_buf)
        return len(write_buf)


class KeyValueList(MySQLDataType):
    """
    Key value list (from handshake response packet)
    """
    def __init__(self, val={}):
        super(KeyValueList, self).__init__()
        self.val = val

    def read_in(self, net_fd):
        kv_size = LengthEncodedInteger(0)
        kv_read = 0
        total_read = kv_size.read_in(net_fd, label='KV_size')
        while kv_read < kv_size.val:
            key = LengthEncodedString(u'')
            kv_read += key.read_in(net_fd, label='KV_key')
            val = LengthEncodedString(u'')
            kv_read += val.read_in(net_fd, label='KV_val')
            self.val[key.val] = val.val
        return total_read + kv_read

    def write_out(self, net_fd):
        raise NotImplemented


class NullBitmap(FixedLengthString):
    pass
