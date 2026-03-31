def window():
    return None

def groupby():
    return None

def algorithm(event):
    file_path = (event.get('file_path') or '').lower()
    uid = event.get('user_id')

    if '/etc/shadow' in file_path and uid and str(uid) != '0':
        return 1.0

    return 0.0


def context(event_data):
    return (
        "Unauthorized access to the /etc/shadow file detected. "
        "UID " + str(event_data.get('user_id')) +
        " attempted to access sensitive credential storage on host " + str(event_data.get('host')) +
        " using process " + str(event_data.get('process_name')) + " and executed command " + str(event_data.get('process_command')) + 
        ". This may indicate credential dumping or password hash extraction."
    )


def criticality():
    return 'CRITICAL'


def tactic():
    return 'Credential Access (TA0006)'


def technique():
    return 'OS Credential Dumping (T1003)'


def artifacts():
    return stats.collect(['host','user_id','process_name','file_path', 'process_id', 'process_command', 'executable'])


def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}