def window():
    return '10m'

def groupby():
    return ['source_ip']

def investigate():
    return "fortigate_session_analyser"
  
def automate():
    return True

def algorithm(event):
    alert_type = event.get('event_alert')
    if alert_type in ['internal_error', 'passwd_invalid', 'name_invalid']:
        if stats.count("alert_warning") == 15:
            stats.resetcount("alert_warning")
            return 0.75
    return 0.0

def context(event_data):
    return str(event_data.get('event_details'))

def criticality():
    return "HIGH"

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'Brute Force (T1110)'

def artifacts():
    return stats.collect(['event_severity', 'event_action', 'event_alert'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}