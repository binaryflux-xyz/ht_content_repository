def window():
    return '15m'

def groupby():
    return ['user']

def algorithm(event):
      
    if event.get('event_action') == 'failed' and 'password check failed' in event.get('event_details'):
        if stats.count('pwd_check') >= 5:
            stats.resetcount('passwd_check')
            return 0.50
    return 0.0

def context(event_data):
    return (
        "Multiple password check failures detected for user {user} on host {host} "
        "by process {proc}. More than 5 failures occurred within 15 minutes."
    ).format(
        user=event_data.get('user'),
        host=event_data.get('host'),
        proc=event_data.get('process_name')
    )


def criticality():
    return 'MEDIUM'

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'Brute Force (T1110)'

def artifacts():
    return stats.collect(['host', 'process_name', 'event_action', 'user'])

def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'username'}