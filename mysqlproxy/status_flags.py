"""
Server status flags
(usually sent by EOF packets)
"""
STATUS_IN_TRANS                  = 0x1
STATUS_AUTOCOMMIT                = 0x2
MORE_RESULTS_EXISTS              = 0x8
STATUS_NO_GOOD_INDEX_USED        = 0x10
STATUS_NO_INDEX_USED             = 0x20
STATUS_CURSOR_EXISTS             = 0x40
STATUS_LAST_ROW_SENT             = 0x80
STATUS_DB_DROPPED                = 0x100
STATUS_NO_BACKSLASH_ESCAPES      = 0x200
STATUS_METADATA_CHANGED          = 0x400
STATUS_QUERY_WAS_SLOW            = 0x800
PS_OUT_PARAMS                    = 0x1000
