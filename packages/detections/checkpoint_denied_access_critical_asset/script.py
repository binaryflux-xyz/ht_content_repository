def window():
    return '5m'
def groupby():
    return ['destination_ip']
def algorithm(event):
    if event['event_action'] == 'Drop' and event['destination_ip'] in tpi.internal_critical_assets():
        if stats.count('source_ip') >= 10:
            return 0.85
    return 0.0
def context(event_data):
    return (
        "Multiple denied access attempts to critical asset "
        + event_data['dst_ip']
        + " from different sources."
    )
def criticality():
    return 'HIGH'
def tactic():
    return 'Initial Access (TA0001)'
def technique():
    return 'Exploit Public-Facing Application (T1190)'
def artifacts():
    return stats.collect(['source_ip', 'destination_ip', 'destination_port', 'event_action'])
def entity(event):
    return {'derived': False, 'value': event['destination_ip'], 'type': 'ip'}
