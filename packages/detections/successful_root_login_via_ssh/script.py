def window():
    return '5m'

def algorithm(event):
    process = event.get('process_name')
    action = (event.get('event_action') or '').lower()
    details = (event.get('event_details') or '').lower()
    user_ip = event.get("source_ip")

    key = 'linux_success_root_login_{}'.format(user_ip)
    if application.get(key):
        return 0.0

    if process == 'sshd' and action == 'accepted' and (
        'accepted password for root' in details or
        'accepted publickey for root' in details
    ):
        application.put(key, True, 3600)
        return 0.75

    return 0.0


def context(event_data):
    return "A successful SSH login to the root account was detected from IP address " + str(event_data.get('source_ip')) + \
           " on host " + str(event_data.get('host')) + ". Such activity is considered highly sensitive as direct root access " + \
           "can allow full control over the system. It is recommended to review whether this access was authorized."


def criticality():
    return 'HIGH'

def tactic():
    return 'Initial Access (TA0001)'

def technique():
    return 'Valid Accounts (T1078)'

def artifacts():
    return stats.collect(['host', 'event_action', 'source_ip', 'process_name', 'process_id', 'source_port'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}