"""
Client to server command handling
"""
from mysqlproxy.packet import ERRPacket

COMMAND_CODES = {
    0x01: 'quit',
    0x02: 'init_db',
    0x03: 'query',
    0x04: 'field_list'
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
        session.send_payload(ERRPacket(
            session.client_capabilities, 9999, 'Wait what?', seq_id=1))
        return False
