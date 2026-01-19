def window():
    return None
def groupby():
    return None
def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
def algorithm(event):
    if event.get('event_id') == 10 and 'lsass.exe' in event.get('target_process'):
        return 1.0
    return 0.0
def context(event_data):
    return "Process " + event_data.get('process_name') + " accessed LSASS memory, possible credential dumping attempt."
def criticality():
    return 'CRITICAL'
def tactic():
    return 'Credential Access (TA0006)'
def technique():
    return 'OS Credential Dumping (T1003)'
def artifacts():
    return stats.collect(['host', 'process_name', 'target_process', 'event_id'])
def entity(event):
    return {'derived': False, 'value': event.get('process_name'), 'type': 'process'}