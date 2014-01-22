"""
Packet encapsulation unit tests
"""
import unittest
from StringIO import StringIO


class PacketChainTest(unittest.TestCase):
    """
    Test MySQL protocol packet read-ins, both single and multi
    """
    def runTest(self):
        """
        Single/multi packet processing
        """
        from mysqlproxy.packet import IncomingPacketChain

        proto_buf = StringIO(b'\x01\x00\x00\x00\x01')
        pchain = IncomingPacketChain()
        pchain.read_in(proto_buf)
        self.assertEquals(pchain.chain_length, 1)
        self.assertEquals(pchain.packet_meta[0].length, 1)
        self.assertEquals(pchain.payload.read(), b'\x01')
        self.assertEquals(pchain.total_length, 1)

        proto_buf = StringIO(b'\xff\xff\xff\x00' + b'\xcc'*0xffffff + b'\x00\x00\x00\x01')
        pchain = IncomingPacketChain()
        pchain.read_in(proto_buf)
        self.assertEquals(pchain.chain_length, 2)
        self.assertEquals(len(pchain.packet_meta), 2)
        self.assertEquals(pchain.packet_meta[0].length, 16777215)
        self.assertEquals(pchain.packet_meta[1].length, 0)
        self.assertEquals(pchain.total_length, 0xffffff)


class ERRPacketTest(unittest.TestCase):
    """
    Test ERRPacket writeout
    """
    def runTest(self):
        """
        run test
        """
        from mysqlproxy.packet import ERRPacket
        from mysqlproxy.capabilities import PROTOCOL_41

        proto_buf = StringIO()
        err_packet = ERRPacket(PROTOCOL_41, 0x448, "No tables used", sql_state='HY000', seq_id=1)
        err_packet.write_out(proto_buf)
        proto_buf.seek(0)
        schtuff = bytes(proto_buf.read())

        self.assertEquals(schtuff, b'\x17\x00\x00\x01\xff\x48\x04#HY000No tables used')
