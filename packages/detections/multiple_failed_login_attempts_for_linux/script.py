def window():
    return '2m'

def groupby():
    return ['source_ip']

def algorithm(event):
    process = event.get('process_name')
    action = (event.get('event_action') or '').lower()
    details = (event.get('event_details') or '').lower()

    if process == 'sshd' and action == 'failed' and (
        'failed password for' in details or 
        'authentication failure' in details
    ):
        if stats.count('source_ip') >= 5:
            stats.resetcount('source_ip')
            return 0.50
    return 0.0

def context(event_data):
    return "Multiple failed SSH login attempts detected on the host " + str(event_data.get('host'))  + " by user " + str(event_data.get('user')) + " using IP "+ str(event_data.get('source_ip')) + " and port " + str(event_data.get('source_port'))  + " with more than 5 attempts in 2 minutes."


def criticality():
    return 'MEDIUM'

def tactic():
    return 'Initial Access (TA0001)'

def technique():
    return 'Brute Force (T1110)'

def artifacts():
    return stats.collect(['host', 'event_action', 'source_ip', 'process_name', 'user', 'source_port', 'process_id', 'event_details'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}