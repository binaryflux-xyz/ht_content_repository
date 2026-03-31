def window():
    return '10m'

def groupby():
    return ['user']

def algorithm(event):
    process = (event.get('process_name') or '').lower()

    if process in ['uname','id','whoami','sudo','cat']:
        return 0.50

    return 0.0


def context(event_data):
    return (
        "System reconnaissance command " + str(event_data.get('process_command')) + " executed by user " +
        str(event_data.get('user')) +
        " on host " + str(event_data.get('host')) +
        ". This may indicate attacker discovery activity."
    )


def criticality():
    return 'MEDIUM'


def tactic():
    return 'Discovery (TA0007)'


def technique():
    return 'System Information Discovery (T1082)'


def artifacts():
    return stats.collect(['host','user','process_name','process_command', 'event_details'])


def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'user'}