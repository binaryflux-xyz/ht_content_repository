def window():
    return '15m'

def groupby():
    return ['user']

def algorithm(event):
    process = event.get('process_name')
    details = (event.get('event_details') or '').lower()
    user = event.get('user')

    if process == 'sudo' and user != 'root' and 'session opened for user root' in details:
        if stats.count('abnormal_sudo') >= 15:
          stats.resetcount('abnormal_sudo')
          return 0.75

    return 0.0



def context(event_data):
    return (
        "Abnormal sudo privilege escalation detected. "
        "User " + str(event_data.get('user')) +
        " initiated a sudo sessions to root " +
        " on host " + str(event_data.get('host')) + " with 15 sessions in 15 minutes duration" +
        ". This may indicate unauthorized privilege escalation and should be reviewed."
    )


def criticality():
    return 'HIGH'

def tactic():
    return 'Privilege Escalation (TA0004)'

def technique():
    return 'Abuse Elevation Control Mechanism (T1548)'

def artifacts():
    stats.collect(['host','process_name','user','event_details', 'user_id', 'event_action'])

def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'user'}