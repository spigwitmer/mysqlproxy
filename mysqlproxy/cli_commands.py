"""
Client to server command handling
"""
from mysqlproxy.packet import ERRPacket, OKPacket, EOFPacket
from mysqlproxy.query_response import ResultSetText, ResultSetRowText, \
    ResultSetBinary, ResultSetRowBinary, ColumnDefinition
from mysqlproxy import column_types
import sys
import socket
from StringIO import StringIO
from datetime import datetime
from pymysql import err
from pymysql.cursors import DictCursor
import logging
import re

_LOG = logging.getLogger(__name__)

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
    0x16: ('stmt_prepare', 'unsupported_client_command'),
    0x17: ('stmt_execute', 'unsupported_client_command'),
    0x18: ('stmt_send_long_data', 'unsupported_client_command'),
    0x19: ('stmt_close', 'unsupported_client_command'),
    0x19: ('stmt_reset', 'unsupported_client_command'),
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
    command_name = COMMAND_CODES[code][0]
    session_obj.send_payload(
        ERRPacket(
            session_obj.client_capabilities,
            error_code=9990,
            error_msg=u'The command "%s" is unsupported by mysqlproxy' % command_name,
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
        _LOG.debug('Received command code %x', cli_command)
        session.send_payload(ERRPacket(
            session.client_capabilities, \
                    error_code=9999, error_msg='Wait what?', seq_id=1))
        return True

    command_name, command_fn_name = COMMAND_CODES[cli_command]
    _LOG.debug('Received command code %x (%s)' % \
            (cli_command, command_fn_name))
    command_fn = globals().get(command_fn_name, unknown_cli_command)
    return command_fn(session, cmd_packet_data[1:], cli_command)


def cli_change_db(session_obj, pkt_data, code):
    schema_name = pkt_data
    response = session_obj.proxy_obj.change_db(schema_name)
    session_obj.send_payload(response)
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
    _LOG.debug('Got query command: %s' % query)
    if query.lower() == 'select @@version_comment limit 1':
        # intercept the MySQL client getting version info, replace with our own
        response = ResultSetText(session_obj.client_capabilities,
            flags=session_obj.server_status)
        col_name = u'@@version_comment'
        row_val = u'mysqlproxy-0.1'
        response.add_column(col_name, column_types.VAR_STRING, len(row_val))
        response.add_row([row_val])
    else:
        proxy = session_obj.proxy_obj
        plugin_continue, plugin_ret = proxy.plugins.call_hooks('com_query',
            query, session_obj)
        if plugin_continue:
            response = proxy.build_response_from_query(query)
        else:
            response = plugin_ret
    session_obj.send_payload(response)
    return True


def cli_command_field_list(session_obj, pkt_data, code):
    table_name, wildcard = pkt_data.split('\x00')[:2]
    if not re.match(r'^[a-zA-Z0-9_]+', table_name):
        session_obj.send_payload(ERRPacket(
            session_obj.client_capabilities, 1049,
            u'Invalid table name', seq_id=1))
        return True

    if not re.match(r'^[a-zA-Z0-9_%]+', table_name):
        session_obj.send_payload(ERRPacket(
            session_obj.client_capabilities, 1049,
            u'Invalid wildcard', seq_id=1))
        return True

    cli_con = session_obj.proxy_obj.client_conn
    field_list = cli_con.get_field_list(table_name, wildcard)
    results = ResultSetText(session_obj.client_capabilities,
        flags=session_obj.server_status)
    for colname, coltype, col_max_len, \
            field_len, field_max_len, _, _ in field_list:
        results.add_column(unicode(colname), coltype, field_len)
    # TODO: server status negoatiation
    tx_packets = results.columns
    for i in range(0, len(tx_packets)):
        tx_packets[i].seq_id = i+1
    tx_eof = EOFPacket(
        session_obj.client_capabilities,
        status_flags=session_obj.server_status,
        seq_id=len(tx_packets)+1)
    tx_packets.append(tx_eof)
    return True
