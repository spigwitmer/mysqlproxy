"""
Binary protocol value handling
"""

from mysqlproxy.types import *
from mysqlproxy import column_types as coltypes
import struct
from datetime import datetime

def generate_binary_field_info(val, type_code):
    """
    Returns a list of data types representing the value
    `val` of type code `type_code` (see mysqlproxy/column_types.py)
    """
    if type_code in [coltypes.STRING, coltypes.VARCHAR, coltypes.VAR_STRING,
        coltypes.ENUM, coltypes.SET, coltypes.LONG_BLOB,
        coltypes.MEDIUM_BLOB, coltypes.BLOB, coltypes.TINY_BLOB,
        coltypes.GEOMETRY, coltypes.BIT, coltypes.DECIMAL,
        coltypes.NEWDECIMAL]:
        return [('str_val', LengthEncodedString(unicode(val)))]
    elif type_code == coltypes.LONGLONG:
        return [('uint64_val', FixedLengthInteger(8, val))]
    elif type_code in [coltypes.LONG, coltypes.INT24]:
        return [('uint32_val', FixedLengthInteger(4, val))]
    elif type_code in [coltypes.SHORT, coltypes.YEAR]:
        return [('uint16_val', FixedLengthInteger(2, val))]
    elif type_code == coltypes.TINY:
        return [('uint8_val', FixedLengthInteger(1, val))]
    elif type_code == coltypes.DOUBLE:
        return [('double_val', FixedLengthString(8, struct.pack('<d', float(val))))]
    elif type_code == coltypes.FLOAT:
        return [('float_val', FixedLengthString(4, struct.pack('<f', float(val))))]
    elif type_code in [coltypes.DATE, coltypes.DATETIME, coltypes.TIMESTAMP]:
        if type(val) in [tuple, list]:
            # we sorta know what we're doing
            try:
                year, month, day, hour, minute, second, micro_second = val
            except:
                # not enough values in tuple/list, so uh, panic
                raise ValueError('val for binary Datetime/Timestamp cannot be parsed')
        elif type(val) == int:
            # assume a UNIX timestamp
            dt = datetime.fromtimestamp(val)
            year, month, day, hour, minute, second, micro_second = \
                dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond
        else:
            raise ValueError('val for binary Datetime/Timestamp cannot be parsed')

        # TODO: 0-val optimizations, length doesn't have to be 11
        return [
            ('packet_length', FixedLengthInteger(1, 11)),
            ('year', FixedLengthInteger(2, year)),
            ('month', FixedLengthInteger(1, month)),
            ('day', FixedLengthInteger(1, day)),
            ('hour', FixedLengthInteger(1, hour)),
            ('minute', FixedLengthInteger(1, minute)),
            ('second', FixedLengthInteger(1, second)),
            ('micro_second', FixedLengthInteger(4, micro_second))
        ]
    elif type_code == coltypes.TIME:
        # time delta
        if type(val) not in [tuple, list]:
            raise ValueError('Cannot parse val for TIME type from type %s', type(val))

        # everything's an integer, right?
        if reduce(lambda x, y: x+y, [int(type(x) != int) for x in val]) == 0:
            raise ValueError('Cannot parse val for TIME type: non-integer value')

        if len(val) == 5:
            # is_negative implied by the sign of the first non-zero value
            for v in val:
                if val != 0:
                    is_negative = (1 if v < 0 else 0)
                    break
            days, hours, minutes, seconds, micro_seconds = [abs(x) for x in list(val)]
        elif len(val) == 6:
            is_negative, days, hours, minutes, seconds, micro_seconds = val
            is_negative = int(is_negative) # if a bool, convert it
        else:
            raise ValueError('val for TIME type is incomplete length (%d)' % len(val))

        # TODO: again, 0-val optimizations
        return [
            ('field_length', FixedLengthInteger(1, 12)),
            ('is_negative', FixedLengthInteger(1, is_negative)),
            ('days', FixedLengthInteger(4, days)),
            ('hours', FixedLengthInteger(1, hours)),
            ('minutes', FixedLengthInteger(1, minutes)),
            ('seconds', FixedLengthInteger(1, seconds)),
            ('micro_seconds', FixedLengthInteger(4, micro_seconds)),
        ]
    else:
        raise ValueError('Invalid column type (code: %d)' % type_code)
