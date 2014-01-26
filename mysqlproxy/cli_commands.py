"""
Client to server command handling
"""
from mysqlproxy.packet import ERRPacket, OKPacket
from mysqlproxy.query_response import ResultSetText, ResultSetRowText, \
    ResultSetBinary, ResultSetRowBinary, ColumnDefinition
from mysqlproxy import column_types
import sys
import socket
from StringIO import StringIO

COMMAND_CODES = {
    0x01: ('quit', 'cli_command_quit'),
    0x02: ('init_db', 'cli_change_db'),
    0x03: ('query', 'cli_command_query'),
    0x04: ('field_list', 'cli_command_field_list'),
    0x05: ('create_db', 'unsupported_client_command'),
    0x06: ('drop_db', 'unsupported_client_command'),
    0x07: ('refresh', 'unsupported_client_command'),
    0x08: ('shutdown', 'unsupported_client_command'),
    0x09: ('statistics', 'unsupported_client_command'),
    0x0a: ('process_info', 'unsupported_client_command'),
    0x0b: ('connect', 'unsupported_client_command'), # internal
    0x0c: ('kill', 'unsupported_client_command'),
    0x0d: ('debug', 'unsupported_client_command'),
    0x0e: ('ping', 'cli_command_ping'),
    0x0f: ('time', 'unsupported_client_command'), # internal
    0x10: ('delayed_insert', 'unsupported_client_command'), # internal
    0x11: ('change_user', 'unsupported_client_command'),
    0x1f: ('reset_connection', 'unsupported_client_command'),
    0x1d: ('daemon', 'unsupported_client_command'), # internal
}

def cli_command_ping(session_obj, pkt, code):
    session_obj.send_payload(
        OKPacket(
            session_obj.client_capabilities,
            0, 0, seq_id=1, info=u'PONG'
            )
        )
    return True

def unsupported_client_command(session_obj, pkt, code):
    command_name = COMMAND_CODES[code]
    session_obj.send_payload(
        ERRPacket(
            session_obj.client_capabilities,
            error_code=9990,
            error_msg=u'The "%s" is unsupported by mysqlproxy' % command_name,
            seq_id=1
        ))
    return True


def unknown_cli_command(session, pkt_data, code):
    session.send_payload(ERRPacket(
        session.client_capabilities, \
                error_code=9997, error_msg='Unimplemented command (%d)' % code, seq_id=1))
    return True


def handle_client_command(session, cmd_packet_data):
    """
    Send response based on command given.
    Return true if server should continue, false if it 
    should disconnect.
    """
    if len(cmd_packet_data) == 0:
        raise ValueError('no command data')
    cli_command = ord(cmd_packet_data[0])
    if cli_command not in COMMAND_CODES:
        print 'Received command code %x' % cli_command
        session.send_payload(ERRPacket(
            session.client_capabilities, \
                    error_code=9999, error_msg='Wait what?', seq_id=1))
        return True

    command_name, command_fn_name = COMMAND_CODES[cli_command]
    print 'Received command code %x (%s)' % \
            (cli_command, command_fn_name)
    command_fn = globals().get(command_fn_name, unknown_cli_command)
    return command_fn(session, cmd_packet_data[1:], cli_command)


def cli_change_db(session, pkt_data, code):
    schema_name = pkt_data
    session.send_payload(ERRPacket(session.client_capabilities, \
        error_code=9999, error_msg='No available databases specified by hooks', seq_id=1))
    return True


def cli_command_quit(session, pkt_data, code):
    try:
        session.send_payload(OKPacket(
            session.client_capabilities, \
            0, 0, seq_id=1, info='no please come back :('))
    except socket.error:
        pass # the hell with it.  Some clients close prematurely anyway.
    return False


def cli_command_query(session_obj, pkt_data, code):
    query = pkt_data
    print 'Got query command: %s' % query

    result_set = ResultSetText(session_obj.client_capabilities,
        flags=session_obj.server_status)

    # XXX
    if query.lower() == 'select @@version_comment limit 1':
        col_name = u'@@version_comment'
        row_val = u'mysqlproxy 0.1 -- 2014 Pat Mac'
    else:
        col_name = u'this_is'
        row_val = u'...not implemented yet'
    result_set.add_column(col_name, column_types.VAR_STRING, len(row_val))
    result_set.add_row([row_val])
    sio = StringIO()
    result_set.write_out(sio)
    sio.seek(0)
    session_obj.net_fd.write(sio.read())
    return True

def cli_command_field_list(session_obj, pkt_data, code):
    payload = [
        ColumnDefinition(u'this',
            column_types.VAR_STRING,
            255 * 3, 0x21, # unicode (with char count 3)
            decimals=31,
            show_default=True,
            seq_id=1
            ),
        ColumnDefinition(u'is',
            column_types.SHORT,
            2, 0x21,
            decimals=0,
            default=29,
            show_default=True,
            seq_id=2
            ),
        ## DATETIME
        # MySQL's source sez:
        # ** In string context: YYYY-MM-DD HH:MM:DD
        # ** In number context: YYYYMMDDHHMMDD
        # this is stored as an int8
        ColumnDefinition(u'a',
            column_types.DATETIME,
            8, 0x21,
            decimals=0,
            default=20070127110000L,
            show_default=True,
            seq_id=3
            ),
        ColumnDefinition(u'test',
            column_types.LONG,
            4, 0x21,
            decimals=2,
            default=1337,
            show_default=True,
            seq_id=4
            ),
        EOFPacket(session_obj.client_capabilities, seq_id=5, status_flags=session_obj.server_status)
    ]
    session_obj.send_payload(columns)
    return True
