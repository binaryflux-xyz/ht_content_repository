def window():
    return None

def groupby():
    return None

def algorithm(event):
    user_ip = event.get('user_ip')
    host = event.get('host')
    key = 'linux_ssh_login_success_{}_{}'.format(user_ip, host)
    key_exists = application.get(key)
    if key_exists is True:
        return 0.0
    if event.get('action') == 'sshd' and 'Accepted publickey for' in event.get('event_message'):
      application.put(key, True, 86400)
      return 0.50
    return 0.0

def context(event_data):
    return "A successful SSH login using a public key was detected from IP address " + event_data.get('user_ip') + \
           " on host " + event_data.get('host') + ". Public key-based authentication is commonly used for secure, automated access."


def criticality():
    return 'MEDIUM'

def tactic():
    return 'Initial Access (TA0001)'

def technique():
    return 'Valid Accounts (T1078)'

def artifacts():
    return stats.collect(['host', 'event_category', 'action', 'user_ip'])

def entity(event):
    return {'derived': False, 'value': event.get('user_ip'), 'type': 'ipaddress'}