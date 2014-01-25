"""
Query response format
"""
from mysqlproxy import column_types
from mysqlproxy.types import *
from mysqlproxy.packet import Packet, EOFPacket, OKPacket, ERRPacket, OutgoingPacketChain
from mysqlproxy import status_flags
from mysqlproxy.binary_protocol import generate_binary_field_info

# in particular, ColumnDefinition41.  Again, 3.2 is not supported.
class ColumnDefinition(Packet):
    def __init__(self, name, column_type, column_length, charset_code, **kwargs):
        super(ColumnDefinition, self).__init__(0, **kwargs)
        self.column_type = column_type
        org_name = kwargs.pop('org_name', u'')
        schema = kwargs.pop('schema', u'')
        table = kwargs.pop('table', u'')
        org_table = kwargs.pop('org_table', u'')
        decimals = kwargs.pop('decimals', 0)
        flags = kwargs.pop('flags', 0)
        show_default = kwargs.pop('show_default', False)
        default_value = kwargs.pop('default', None)
        self.fields = [
            ('catalog', LengthEncodedString(u'def')),
            ('schema', LengthEncodedString(schema)),
            ('table', LengthEncodedString(table)),
            ('org_table', LengthEncodedString(org_table)),
            ('name', LengthEncodedString(name)),
            ('org_name', LengthEncodedString(org_name)),
            ('next_length', LengthEncodedInteger(0x0c)),
            ('charset', FixedLengthInteger(2, charset_code)),
            ('column_length', FixedLengthInteger(4, column_length)),
            ('column_type', FixedLengthInteger(1, column_type)),
            ('flags', FixedLengthInteger(2, flags)),
            ('decimals', FixedLengthInteger(1, decimals)),
            ('filler', FixedLengthString(2, '\x00\x00'))
            ]
        if show_default:
            self.fields += [
                ('default_len', LengthEncodedInteger(len(default_value) if default_value else 0)),
                ('default_value', FixedLengthString(default_value))
                ]


class ResultSetRowText(Packet):
    """
    Actual values for the returned rows
    """
    def __init__(self, values, **kwargs):
        super(ResultSetRowText, self).__init__(0, **kwargs)
        self.fields = []
        for val, pos in [(values[x], x) for x in range(0, len(values))]:
            if val != None:
                val_field = LengthEncodedString(str(val))
            else: # 0xfb is considered null for a column value
                val_field = FixedLengthString(1, '\xfb')
            self.fields.append(('val_%d' % pos, val_field))


def ResultSetRowBinary(Packet):
    def __init__(self, column_info, values, **kwargs):
        super(ResultSetRowBinary, self).__init__(0, **kwargs)

        # the binary protocol keeps a bitmap of positions of all the
        # field values that are null
        bitmap_len = (len(self.values) + 7 + 2) / 8
        null_bitmap = '\x00' * bitmap_len
        value_fields = []
        for val, pos in [(values[x], x) for x in range(0, len(values))]:
            col_info = column_info[x]
            if val == None:
                null_bitmap[(pos + 2) / 8] |= 1 << ((pos + 2) % 8)
            else:
                value_fields += generate_binary_field_info(val, col_info.column_type)
        self.fields = [FixedLengthString(bitmap_len, null_bitmap)] + value_fields

class ResultSet(object):
    def __init__(self, client_capabilities, columns, col_values, seq_id=1, more_results=False, flags=0):
        """
        columns -- list of ColumnDefinition objects
        col_values -- 2d list of respective values
        more_results -- True if there are actually more results than given
            (this is just a server-status reported to the client)
        """
        self.client_capabilities = client_capabilities
        self.columns = columns
        self.col_values = col_values
        self.more_results = more_results
        self.seq_id = seq_id
        self.flags = flags

    def write_out(self, net_fd):
        colinfo_written, next_seq_id = self.send_column_info(net_fd, self.seq_id)
        rowinfo_written, last_seq_id = self.send_row_info(net_fd, next_seq_id)
        return (colinfo_written+rowinfo_written, last_seq_id)


class ResultSetText(ResultSet):
    def send_column_info(self, net_fd, seq_id):
        server_status_flags = self.flags | \
            (0 if not self.more_results else status_flags.MORE_RESULTS_EXISTS)
        num_cols = len(self.columns)
        if num_cols == 0 or len(self.col_values) == 0:
            return OKPacket(self.client_capabilities, 0, 0, seq_id=self.seq_id).write_out(net_fd)
        opc = OutgoingPacketChain(start_seq_id=seq_id)
        opc.add_field(LengthEncodedInteger(num_cols))
        total_written, seq_id = opc.write_out(net_fd)
        for column in self.columns:
            column.seq_id = seq_id+1
            col_bytes_written, seq_id = column.write_out(net_fd)
            total_written += col_bytes_written
        eof_written, seq_id = EOFPacket(
            self.client_capabilities,
            seq_id=seq_id+1,
            status_flags=server_status_flags).write_out(net_fd)
        total_written += eof_written
        return total_written, seq_id

    def send_row_info(self, net_fd, seq_id):
        for row in self.col_values:
            row.seq_id = seq_id+1
            row_bytes_written, seq_id = row.write_out(net_fd)
            total_written += row_bytes_written
        eof_written, seq_id = EOFPacket(
            self.client_capabilities,
            seq_id=seq_id+1,
            status_flags=server_status_flags).write_out(net_fd)
        return total_written, seq_id


class ResultSetBinary(ResultSetText):
    def send_row_info(self, net_fd, seq_id):
        if not server_status_flags & status_flags.STATUS_CURSOR_EXISTS:
            return super(ResultSetBinary, self).send_row_info(net_fd, seq_id)
