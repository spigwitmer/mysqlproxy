"""
pymsyql client overrides
"""
from pymysql.connections import Connection, MysqlPacket, \
                                FieldDescriptorPacket
from pymysql.util import byte2int
from pymysql.constants.COMMAND import COM_FIELD_LIST
import struct


class FieldDescriptorOrEOFPacket(FieldDescriptorPacket):
    """
    Like FieldDescriptorPacket, but don't parse
    field info if it's just an EOF packet.
    This is used for COM_FIELD_LIST
    FIXME: lots and lots of pointless copy-paste fodder from pymysql
    """
    def __init__(self, connection):
        MysqlPacket.__init__(self, connection)
        self.check_error()
        if not self.is_eof_packet():
            self.__parse_field_descriptor(connection.encoding)

    def __parse_field_descriptor(self, encoding):
        """Parse the 'Field Descriptor' (Metadata) packet.

        This is compatible with MySQL 4.1+ (not compatible with MySQL 4.0).
        """
        self.catalog = self.read_length_coded_string()
        self.db = self.read_length_coded_string()
        self.table_name = self.read_length_coded_string().decode(encoding)
        self.org_table = self.read_length_coded_string().decode(encoding)
        self.name = self.read_length_coded_string().decode(encoding)
        self.org_name = self.read_length_coded_string().decode(encoding)
        self.advance(1)  # non-null filler
        self.charsetnr = struct.unpack('<H', self.read(2))[0]
        self.length = struct.unpack('<I', self.read(4))[0]
        self.type_code = byte2int(self.read(1))
        self.flags = struct.unpack('<H', self.read(2))[0]
        self.scale = byte2int(self.read(1))  # "decimals"
        self.advance(2)  # filler (always 0x00)

        # 'default' is a length coded binary and is still in the buffer?
        # not used for normal result sets...


class ProxyConnection(Connection):
    def get_field_list(self, table_name, wildcard=None):
        ''' Get column information for a table '''
        table_name = table_name + '\x00'
        self._execute_command(COM_FIELD_LIST, table_name+wildcard)
        self._fields_meta = self._read_field_list_result()
        return self._fields_meta

    def _read_field_list_result(self):
        fields_meta = []
        read_packet = self._read_packet(FieldDescriptorOrEOFPacket)
        while not read_packet.is_eof_packet():
            fields_meta.append(read_packet.description())
            read_packet = self._read_packet(FieldDescriptorOrEOFPacket)
        return fields_meta
