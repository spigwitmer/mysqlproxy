"""
Client to server command handling
"""
from mysqlproxy.packet import ERRPacket, OKPacket
from mysqlproxy.query_response import ResultSet, ResultSetRow, ColumnDefinition
from mysqlproxy import column_types
import sys
import socket
from StringIO import StringIO

COMMAND_CODES = {
    0x01: ('quit', 'cli_command_quit'),
    0x02: ('init_db', 'cli_change_db'),
    0x03: ('query', 'cli_command_query'),
    #0x04: 'field_list'
}


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

    # XXX
    if query.lower() == 'select @@version_comment limit 1':
        version_comment = u'mysqlproxy 0.1 -- 2014 Pat Mac'
        cd = ColumnDefinition(u'@@version_comment',
            column_types.VAR_STRING,
            len(version_comment) * 3,
            0x21,
            decimals=31,
            org_name=u''
            )
        row = ResultSetRow([version_comment])
        result_set = ResultSet(
                session_obj.client_capabilities,
                [cd], [row], seq_id=1, flags=session_obj.server_status)
    else:
        row_val = u'...not implemented yet'
        cd = ColumnDefinition(u'This is...',
            column_types.VAR_STRING,
            len(row_val) * 3, 0x21,
            decimals=31, org_name=u''
            )
        row = ResultSetRow([row_val])
        result_set = ResultSet(
            session_obj.client_capabilities,
            [cd], [row], seq_id=1, flags=session_obj.server_status)
    sio = StringIO()
    result_set.write_out(sio)
    sio.seek(0)
    session_obj.net_fd.write(sio.read())
    return True

def cli_command_field_list(session_obj, pkt_data, code):
    pass #XXX