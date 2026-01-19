def window():
    return '10m'

def groupby():
    return ['source_device_name']
  
def investigate():
    return "fortigate_session_analyser"
  
def automate():
    return True


def algorithm(event):
    details = event.get('event_details')
    if not details:
        return 0.0

    # Make case-insensitive comparison
    if 'failed to connect fortianalyzer' in details.lower():
        count = stats.count("fortianalyzer")
        if count >= 3:
            stats.resetcount("fortianalyzer")
            return 0.5

    return 0.0

def context(event_data):
    return str(event_data.get('event_details')) + "for the device" + str(event_data.get('source_device_name')) + " with more than 3 attempts."

def criticality():
    return 'MEDIUM'

def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Impair Defenses (T1562)'

def artifacts():
    return stats.collect(['event_severity', 'event_action', 'event_alert', 'log_subtype', 'source_ip', 'destination_ip'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}

