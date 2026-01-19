#Detection 1: Port Scanning Behavior (Internal Reconnaissance)

def window():
    return '5m'

def groupby():
    return ['source_ip']

def algorithm(event):
    if event['log_type'] == 'traffic' and event.get("event_action") == 'deny' and event['network_protocol'] in ['TCP', 'UDP', 'UDP-137'] and stats.count(event.get('source_ip')):
      return 0.0

    elif  event['log_type'] == 'traffic' and event.get("event_action") != 'deny' and event['network_protocol'] in ['TCP', 'UDP', 'UDP-137']:
      stats.getcount(event.get('source_ip')) > 3
      return 0.5

def context(event_data):
    return (
        "User " + str(event_data.get('user_name', 'unknown')) +
        " from IP " + str(event_data.get('source_ip', 'unknown')) +
        " had 3 VPN login failures followed by a successful login using method " +
        str(event_data.get('auth_method', 'unspecified')) +
        " on device " + str(event_data.get('source_device_name', 'unspecified'))
    )


def criticality():
    return 'MEDIUM'

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'Brute Force (T1110)'

def artifacts():
    return stats.collect(['source_ip', 'user_name', 'network_protocol', 'destination_port','auth_method'])

def entity(event):
    return {'derived': False, 'value': event['source_ip'], 'type': 'ipaddress'}