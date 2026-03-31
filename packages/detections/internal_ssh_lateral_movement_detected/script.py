def window():
    return '10m'

def groupby():
    return ['user']

def algorithm(event):
    process = (event.get('process_name') or '').lower()
    action = (event.get('event_action') or '').lower()
    user = event.get('user')

    if process == 'sshd' and action == 'accepted' and user:

        user = stats.accumulate(['user'])
        unique_user=len(dest_port.get("user"))
        if unique_user >= 3:
          stats.dissipate(['user'])
          return 0.75

    return 0.0



def context(event_data):
    return (
        "Multiple internal SSH connections detected from host " + str(event_data.get('host')) + " by user " + str(event_data.get('user')) + " from source ip " + str(event_data.get('source_ip')) + " and port " + str(event_data.get('source_port')) +
        " to several internal systems. This may indicate lateral movement activity."
    )


def criticality():
    return 'HIGH'


def tactic():
    return 'Lateral Movement (TA0008)'


def technique():
    return 'Remote Services (T1021)'

def artifacts():
    return stats.collect(['host','process_name','user', 'event_action', 'source_ip', 'source_port', 'event_details'])


def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'user'}