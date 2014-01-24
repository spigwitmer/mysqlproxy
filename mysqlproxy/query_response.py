"""
Query response format
"""
from mysqlproxy import column_types
from mysqlproxy.types import *
from mysqlproxy.packet import Packet, EOFPacket, OKPacket, ERRPacket, OutgoingPacketChain
from mysqlproxy import status_flags

# in particular, ColumnDefinition41.  Again, 3.2 is not supported.
class ColumnDefinition(Packet):
    def __init__(self, name, column_type, column_length, charset_code, **kwargs):
        super(ColumnDefinition, self).__init__(0, **kwargs)
        org_name = kwargs.pop('org_name', name)
        schema = kwargs.pop('schema', u'')
        table = kwargs.pop('table', u'')
        org_table = kwargs.pop('org_table', table)
        decimals = kwargs.pop('decimals', 0)
        flags = kwargs.pop('flags', 0)
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
            ('decimals', FixedLengthInteger(1, decimals))
            ]


class ResultSetRow(Packet):
    """
    Actual values for the returned rows
    """
    def __init__(self, values, **kwargs):
        super(ResultSetRow, self).__init__(0, **kwargs)
        self.fields = []
        for val, pos in [(values[x], x) for x in range(0, len(values))]:
            if val:
                val_field = LengthEncodedString(str(val))
            else: # 0xfb is considered null for a column value
                val_field = FixedLengthString(1, '\xfb')
            self.fields.append(
                ('val_%d' % pos, val_field)
                )


class ResultSet(object):
    """
    Writes response to COM_QUERY commands.
    Will write multiple packets over the wire:
    column_count --> ColumnDefinition packets --> 
        EOF --> ResultSetRow packets --> EOF/ERR
    """
    def __init__(self, client_capabilities, columns, col_values, seq_id=1, more_results=False):
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

    def write_out(self, net_fd):
        num_cols = len(self.columns)
        if num_cols == 0 or len(self.col_values) == 0:
            return OKPacket(self.client_capabilities, 0, 0, seq_id=self.seq_id).write_out(net_fd)
        opc = OutgoingPacketChain()
        opc.seq_id = self.seq_id
        opc.add_field(LengthEncodedInteger(num_cols))
        total_written, seq_id = opc.write_out(net_fd)
        for column in self.columns:
            column.seq_id = seq_id+1
            col_bytes_written, seq_id = column.write_out(net_fd)
            total_written += col_bytes_written
        eof_written, seq_id = EOFPacket(
            self.client_capabilities,
            seq_id=seq_id+1).write_out(net_fd)
        total_written += eof_written
        for row in self.col_values:
            row.seq_id = seq_id+1
            row_bytes_written, seq_id = row.write_out(net_fd)
            total_written += row_bytes_written
        server_status_flags = 0 if not self.more_results else status_flags.MORE_RESULTS_EXISTS
        eof_written, seq_id = EOFPacket(
            self.client_capabilities,
            seq_id=seq_id+1,
            status_flags=server_status_flags).write_out(net_fd)
        return total_written, seq_id
