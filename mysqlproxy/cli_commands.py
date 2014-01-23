"""
Client to server command handling
"""
from mysqlproxy.packet import ERRPacket, OKPacket
import sys

COMMAND_CODES = {
    0x01: 'quit',
    #0x02: 'init_db',
    0x03: 'query',
    #0x04: 'field_list'
}

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
        return False

    command_fn_name = COMMAND_CODES[cli_command]
    print 'Received command code %x (%s)' % \
            (cli_command, command_fn_name)
    command_fn = getattr(sys.modules[__name__], \
            command_fn_name, unknown_cli_command)
    return command_fn(session, cmd_packet_data, cli_command)
            
def unknown_cli_command(session, pkt_data, code):
    session.send_payload(ERRPacket(
        session.client_capabilities, \
                error_code=9997, error_msg='Unimplemented command (%d)' % code, seq_id=1))
    pass

def cli_command_quit(session, pkt_data, code):
    print 'Got quit command, sending OK and exiting'
    session.send_payload(OKPacket())
    return False

def cli_command_query(session, pkt_data, code):
    query = pkt_data
    print 'Got query command: %s' % query
    session.send_payload(ERRPacket(
        session.client_capabilities, \
                error_code=9998, error_msg='AM DO THINGS LOL', seq_id=1))
    return False
