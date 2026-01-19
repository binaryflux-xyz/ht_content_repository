def window():
    return '10m'

def groupby():
    return ['user_ip']

def algorithm(event):
    user_ip = event.get('user_ip')
    key = 'linux_sudo_command_from_root_{}'.format(user_ip)
    key_exists = application.get(key)
    if key_exists is True:
        return 0.0
    if event.get('action') == 'sudo' and 'root : PWD=/root' in event.get('event_message'):
        if stats.count('user_ip') > 3:
            application.put(key, True, 86400)
            return 0.50
    return 0.0

def context(event_data):
    return "Root Directory was accessed using the sudo permissions for the user_ip " + event_data.get('user_ip')

def criticality():
    return 'MEDIUM'

def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Obfuscated Files or Information (T1027)'

def artifacts():
    return stats.collect(['hostname', 'event_category', 'action', 'user_ip'])

def entity(event):
    return {'derived': False, 'value': event.get('user_ip'), 'type': 'ipaddress'}