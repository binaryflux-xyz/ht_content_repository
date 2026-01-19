def window():
    return '5m'
def groupby():
    return 'destination_security_id'
def algorithm(event):
    if event['event_name'] == 'Behavior Monitoring' and event.get('event_type') == 'Ransomware':
        return 0.98
    return 0.0
def context(event_data):
    return (
        "Ransomware behavior detected on host " + event_data['destination_security_id'] +
        " involving process " + event_data.get('process_name', 'unknown') + "."
    )
def criticality():
    return 'CRITICAL'
def tactic():
    return 'Impact (TA0040)'
def technique():
    return 'Data Encrypted for Impact (T1486)'
def artifacts():
    return stats.collect(['destination_security_id', 'process_name', 'file_path', 'event_type'])
def entity(event):
    return {'derived': False, 'value': event['destination_security_id'], 'type': 'host'}