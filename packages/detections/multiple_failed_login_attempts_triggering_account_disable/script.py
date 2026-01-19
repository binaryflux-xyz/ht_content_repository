def window():
    return None

def groupby():
    return None

def investigate():
    return "fortigate_session_analyser"
  
def automate():
    return True

def algorithm(event):  
    if (
        event.get('event_action') == 'login' and 
        event.get('event_alert') == 'exceed_limit' and 
        'Login disabled from' in str(event.get('event_details'))):
            return 0.75
    return 0.0

def context(event_data):
    return str(event_data.get('event_details')) + " due to " + str(event_data.get('event_alert'))

def criticality():
    return 'HIGH'

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'Brute Force (T1110)'

def artifacts():
    return stats.collect(['event_severity', 'event_action', 'event_alert'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}