"""
Data type unit tests
"""
import unittest
from StringIO import StringIO

class IntegerTest(unittest.TestCase):
    """
    Test MySQL protocol integer types
    """
    def runTest(self):
        """
        Test Length-Encoded integer read-ins
        """
        from mysqlproxy.types import LengthEncodedInteger

        # wire read
        proto_buf = StringIO(b'\xfa\xfc\xfb\x00')
        lei = LengthEncodedInteger(33)
        lei.read_in(proto_buf)
        self.assertEqual(lei.val, 250)
        lei.read_in(proto_buf)
        self.assertEqual(lei.val, 251)

        # wire writes
        expected_buf = b'\xfa\xfc\xfb\x00\xfd\x01\x00\x01'
        proto_buf = StringIO()
        lei = LengthEncodedInteger(250)
        lei.write_out(proto_buf)
        lei = LengthEncodedInteger(251)
        lei.write_out(proto_buf)
        lei = LengthEncodedInteger(65537)
        lei.write_out(proto_buf)
        self.assertEqual(proto_buf.getvalue(), expected_buf)

class FixedLengthIntegerTest(unittest.TestCase):
    """
    Test MySQL protocol fixed length integers
    """
    def runTest(self):
        """
        Test fixed-length integer read-in
        """
        from StringIO import StringIO
        from mysqlproxy.types import FixedLengthInteger

        # wire read tests
        proto_buf = StringIO(b'\x01\x00\x00\x25')
        fli = FixedLengthInteger(3)
        fli.read_in(proto_buf)
        self.assertEqual(fli.val, 1)

        # wire write tests
        proto_buf = StringIO()
        fli = FixedLengthInteger(3, 1)
        fli.write_out(proto_buf)
        self.assertEqual(proto_buf.getvalue(), b'\x01\x00\x00')

