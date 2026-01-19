def window():
    return '10m'

def groupby():
    return ['user_ip']

def algorithm(event):
    user_ip = event.get("user_ip")
    key = 'linux_multi_login_attempts_{}'.format(user_ip)
    key_exists = application.get(key)
    if key_exists is True:
        return 0.0

    if event.get('action') == 'sshd' and 'Failed password for' in event.get('event_message'):
        if stats.count('user_ip') > 3:
            application.put(key, True, 86400)
            return 0.50
    return 0.0

def context(event_data):
    return "Multiple failed SSH login attempts detected from the IP address " + event_data.get('user_ip')

def criticality():
    return 'MEDIUM'

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'Brute Force (T1110)'

def artifacts():
    return stats.collect(['host', 'event_category', 'action', 'user_ip'])

def entity(event):
    return {'derived': False, 'value': event.get('user_ip'), 'type': 'ipaddress'}