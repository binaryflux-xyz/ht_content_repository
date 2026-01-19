def window():
    return None
def groupby():
    return None
def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
def algorithm(event):
    if event.get('event_id') == 4657 and 'Run' in event.get('registry_path'):
        return 0.75
    return 0.0
def context(event_data):
    return "Suspicious registry modification detected in " + event_data.get('registry_path')
def criticality():
    return 'HIGH'
def tactic():
    return 'Persistence (TA0003)'
def technique():
    return 'Registry Run Keys / Startup Folder (T1547.001)'
def artifacts():
    return stats.collect(['host', 'registry_path', 'event_id'])
def entity(event):
    return {'derived': False, 'value': event.get('registry_path'), 'type': 'registry'}