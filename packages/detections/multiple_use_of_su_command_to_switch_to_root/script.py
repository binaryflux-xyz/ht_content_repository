def window():
    return None

def groupby():
    return None

def algorithm(event):
    hostname = event.get('hostname')
    user_ip = event.get('user_ip')
    key = 'linux_use_of_su_{}_{}'.format(hostname, user_ip)
    key_exists = application.get(key)
    if key_exists is True:
        return 0.0

    if event.get('action') == 'su' and 'Successful su for root' in event.get('event_message'):
      application.put(key, True, 86400)
      return 0.75
    return 0.0

def context(event_data):
    return "A user successfully switched to root using the 'su' command from host " + event_data.get('hostname') + " with source IP " + event_data.get('user_ip')

def criticality():
    return 'HIGH'

def tactic():
    return 'Privilege Escalation (TA0004)'

def technique():
    return 'Abuse Elevation Control Mechanism (T1548)'

def artifacts():
    return stats.collect(['hostname', 'event_category', 'action', 'user_ip'])

def entity(event):
    return {'derived': False, 'value': event.get('user_ip'), 'type': 'ipaddress'}