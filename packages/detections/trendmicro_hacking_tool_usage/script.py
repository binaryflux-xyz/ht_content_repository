def window():
    return '10m'
def groupby():
    return 'destination_security_id'
def algorithm(event):
    if event['event_name'] == 'Spyware/Grayware Detected' and event.get('file_name', '').lower() in ['mimikatz.exe', 'ncat.exe', 'meterpreter.exe']:
        return 0.95
    return 0.0
def context(event_data):
    return (
        "Hacking tool " + event_data['file_name'] + " detected on host " +
        event_data['destination_security_id'] + "."
    )
def criticality():
    return 'HIGH'
def tactic():
    return 'Credential Access (TA0006)'
def technique():
    return 'OS Credential Dumping (T1003.001)'
def artifacts():
    return stats.collect(['destination_security_id', 'file_name', 'malware_name', 'file_path'])
def entity(event):
    return {'derived': False, 'value': event['destination_security_id'], 'type': 'host'}