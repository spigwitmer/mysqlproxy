"""
Wire-level packet handling
"""
from mysqlproxy.types import FixedLengthInteger, \
        FixedLengthString, LengthEncodedInteger, \
        RestOfPacketString
from mysqlproxy import capabilities
from StringIO import StringIO

__all__ = [
    'PacketMeta', 'IncomingPacketChain', 'OutgoingPacketChain',
    'Packet', 'OKPacket', 'ERRPacket', 'EOFPacket'
    ]

class PacketMeta(object):
    """
    Useful packet metadata for chains
    """
    def __init__(self, length, seq_id):
        self.length = length
        self.seq_id = seq_id


class IncomingPacketChain(object):
    """
    List of packets containing one payload
    """
    def __init__(self):
        self.packet_meta = []
        self.payload = None

    def read_in(self, fde):
        """
        Read in full payload
        """
        total_read = 0
        packet_length = FixedLengthInteger(3, 0xffffff)
        seq_id = FixedLengthInteger(1)
        self.payload = StringIO()
        while packet_length.val == 0xffffff:
            packet_length.read_in(fde)
            seq_id.read_in(fde)
            cur_payload = FixedLengthString(packet_length.val)
            cur_payload.read_in(fde)
            self.payload.write(cur_payload.val)
            self.packet_meta.append(PacketMeta(packet_length.val, seq_id.val))
            total_read += packet_length.val
        self.payload.seek(0)
        return total_read

    @property
    def chain_length(self):
        """
        Amount of packets needed to be read to retrieve
        the entire payload
        """
        return len(self.packet_meta)

    @property
    def total_length(self):
        """
        Total payload length
        """
        return sum([x.length for x in self.packet_meta])


class OutgoingPacketChain(object):
    def __init__(self, start_seq_id=0):
        self.fields = []
        self.start_seq_id = start_seq_id

    def add_field(self, field):
        """
        Add field to payload
        """
        self.fields.append(field)

    def _write_packet_header(self, length, seq, fde):
        """
        Write out packet header with given length
        and sequence id to file-like fde
        """
        length_field = FixedLengthInteger(3, length)
        seq_field = FixedLengthInteger(1, seq)
        length_field.write_out(fde)
        seq_field.write_out(fde)

    def write_out(self, fde):
        """
        Write out full packet chain
        """
        # TODO: impl is just outright terrible.
        # Fix it in any way shape or form i don't care
        sio = StringIO()
        seq_id = self.start_seq_id
        net_total_written = 0
        total_written = 0
        last_total_written = 0xffffff
        for field in self.fields:
            written = field.write_out(sio)
            total_written += written
            net_total_written += written
            if total_written >= 0xffffff:
                self._write_packet_header(0xffffff, seq_id, fde)
                fde.write(sio.read(0xffffff))
                remaining_bytes = sio.read()
                sio.close()
                sio = StringIO(remaining_bytes)
                last_total_written = total_written
                total_written -= 0xffffff
                seq_id += 1
        if last_total_written == 0xffffff:
            self._write_packet_header(total_written, seq_id, fde)
            sio.seek(0)
            fde.write(sio.read(total_written))
            net_total_written += total_written
        return net_total_written


class Packet(object):
    """
    Interface class for extracting fields expected out of a single packet
    or writing them out in order.
    """
    def __init__(self, capabilities, **kwargs):
        self.capabilities = capabilities
        self.fields = []
        self.seq_id = kwargs.pop('seq_id', 0)

    def read_in(self, fde):
        """
        Generic read-in of all fields
        """
        ipc = IncomingPacketChain()
        ipc.read_in(fde)
        return self.read_in_internal(ipc.payload)

    def read_in_internal(self, pl_fd):
        """
        This is what you actually want to extend to 
        do custom payload reading
        """
        read_length = 0
        for _, field in self.fields:
            read_length += field.read_in(pl_fd)
        return read_length


    def write_out(self, fde):
        """
        Generic write-out of all fields
        """
        opc = OutgoingPacketChain(start_seq_id=self.seq_id)
        for _, field in self.fields:
            opc.add_field(field)
        return opc.write_out(fde)

    def get_field(self, field_of_interest):
        """
        Return first field going by name `field_of_interest`
        """
        for field_name, field in self.fields:
            if field_name == field_of_interest:
                return field
        raise ValueError('field name %s does not exist' % field_of_interest)


class OKPacket(Packet):
    """
    Generic OK packet, will most likely not be read in
    """
    def __init__(self, capability_flags, affected_rows, last_insert_id, **kwargs):
        super(OKPacket, self).__init__(capability_flags, **kwargs)
        self.affected_rows = affected_rows
        self.last_insert_id = last_insert_id
        use_41 = capability_flags & capabilities.PROTOCOL_41
        transactions = capability_flags & capabilities.TRANSACTIONS
        if use_41 or transactions:
            self.status_flags = kwargs.pop('status_flags', 0)
            self.warnings = kwargs.pop('warnings', 0)
        self.fields = [
            ('ok_header', FixedLengthInteger(1, 0)), # OK header
            ('affected_rows', LengthEncodedInteger(affected_rows)),
            ('last_insert_id', LengthEncodedInteger(last_insert_id))
            ]
        if use_41:
            self.fields += [
                ('status_flags', FixedLengthInteger(2, self.status_flags)),
                ('warnings', FixedLengthInteger(2, self.warnings))
                ]
        elif transactions:
            self.fields.append(('status_flags', FixedLengthInteger(2, self.status_flags)))
        self.fields.append(('ok_message', RestOfPacketString("k thanks")))


class ERRPacket(Packet):
    """
    Error packet
    """
    def __init__(self, capability_flags, error_code, error_msg, **kwargs):
        super(ERRPacket, self).__init__(capability_flags, **kwargs)
        self.error_code = error_code
        self.error_msg = error_msg
        self.fields = [
            ('err_header', FixedLengthInteger(1, 0xff)), # ERR header
            ('error_code', FixedLengthInteger(2, error_code))
            ]
        if capability_flags & capabilities.PROTOCOL_41:
            self.fields += [
                ('sql_state_flag', FixedLengthString(1, '#')),
                ('sql_state', FixedLengthString(5, kwargs.pop('sql_state', 'HY000')))
                ]
        self.fields.append(('error_msg', RestOfPacketString(self.error_msg)))


class EOFPacket(Packet):
    """
    EOF Packet
    """
    def __init__(self, capability_flags, **kwargs):
        super(EOFPacket, self).__init__(capability_flags, **kwargs)
        self.fields = [
            ('eof_header', FixedLengthInteger(1, 0xfe)) # EOF header
            ]
        if capability_flags & capabilities.PROTOCOL_41:
            self.fields += [
                ('warnings', FixedLengthInteger(2, kwargs.pop('warnings', 0))),
                ('status_flags', FixedLengthInteger(2, kwargs.pop('status_flags', 0)))
                ]
