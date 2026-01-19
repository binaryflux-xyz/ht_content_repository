def window():
    return '1d'

def groupby():
    return ['user_ip']

def algorithm(event):
    user_ip = event.get("user_ip")
    key = 'linux_success_root_login_{}'.format(user_ip)
    key_exists = application.get(key)
    if key_exists is True:
        return 0.0
    if event.get('action') == 'sshd' and 'Accepted password for root' in event.get('event_message'):
        if stats.getcount(user_ip) == 4:
            application.put(key, True, 86400)
            return 0.75
        else:
          stats.count(user_ip)     
    return 0.0


def context(event_data):
    return "A successful SSH login to the root account was detected from IP address " + event_data.get('user_ip') + \
           " on host " + event_data.get('host') + ". Such activity is considered highly sensitive as direct root access " + \
           "can allow full control over the system. It is recommended to review whether this access was authorized."


def criticality():
    return 'HIGH'

def tactic():
    return 'Initial Access (TA0001)'

def technique():
    return 'Valid Accounts (T1078)'

def artifacts():
    return stats.collect(['host', 'event_category', 'action', 'user_ip'])

def entity(event):
    return {'derived': False, 'value': event.get('user_ip'), 'type': 'ipaddress'}