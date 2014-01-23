"""
Query response format
"""
from mysqlproxy import column_types
from mysqlproxy.types import *
from mysqlproxy.packet import Packet, OutgoingPacketChain

# in particular, ColumnDefinition41.  Again, 3.2 is not supported.
class ColumnDefinition(Packet):
    def __init__(self, name, column_type, column_length, charset_code, **kwargs):
        super(ColumnDefinition, self).__init__(0, **kwargs)
        schema = kwargs.pop('schema', u'')
        table = kwargs.pop('table', u'')
        decimals = kwargs.pop('decimals', 0)
        self.fields = [
            ('catalog', LengthEncodedString(u'def')),
            ('schema', LengthEncodedString(schema)),
            ('table', LengthEncodedString(table)),
            ('org_table', LengthEncodedString(org_table)),
            ('name', LengthEncodedString(name)),
            ('org_name', LengthEncodedString(name)),
            ('next_length', LengthEncodedInteger(0x0c)),
            ('charset', FixedLengthInteger(2, charset_code)),
            ('column_length', FixedLengthInteger(4, column_length)),
            ('column_type', FixedLengthInteger(1, column_type)),
            ('flags', FixedLengthInteger(2, 0)), # XXX
            ('decimals', FixedLengthInteger(1, decimals))
            ]


class ResultSetRow(Packet):
    """
    Actual values for the returned rows
    """
    def __init__(self, values, **kwargs):
        super(ResultSetRow, self).__init__(0, **kwargs)
        self.fields = []
        for val, pos in [(values[x], x) for x in range(0, len(values)]:
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
    def __init__(self, columns, col_values, **kwargs):
        """
        columns -- list of ColumnDefinition objects
        col_values -- 2d list of respective values
        """
        self.columns = columns
        self.col_values = col_values

    def write_out(self, net_fd):
        num_cols = len(self.columns)
        opc = OutgoingPacketChain()
        opc.add_field(LengthEncodedInteger(num_cols))
        opc.write_out(net_fd)
