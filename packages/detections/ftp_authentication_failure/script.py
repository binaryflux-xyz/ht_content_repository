def window():
    return None

def groupby():
    return ['user']

def algorithm(event):
    key = application.get("ftp_fail")
    if key is True:
        return 0.0

    if event.get('event_action') == 'authentication' and 'authentication failure' in event.get('event_details'):
        application.put("ftp_fail", True, 86400)
        return 0.50
    return 0.0

def context(event_data):
    return "FTP login failed for user " + event_data.get('user') + " on " + event_data.get('host') + " using process " + event_data.get('process_name')
  
def criticality():
    return 'MEDIUM'

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'Brute Force (T1110)'

def artifacts():
    return stats.collect(['host', 'process_name', 'event_action', 'remote_host', 'remote_host'])

def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'username'}