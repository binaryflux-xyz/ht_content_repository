def window():
    return '5m'
def groupby():
    return ['source_ip']
def algorithm(event):
    if event['destination_port'] in [22, 3389, 5985, 5986] and event['destination_ip'] in tpi.internal_subnet():
        if stats.count_distinct('destination_ip') >= 5:
            return 0.92
    return 0.0
def context(event_data):
    return (
        "Internal host " + event_data['source_ip']
        + " attempted to access multiple internal systems via admin ports "
        "(e.g., SSH/RDP/WinRM)."
    )
def criticality():
    return 'CRITICAL'
def tactic():
    return 'Lateral Movement (TA0008)'
def technique():
    return 'Remote Services (T1021)'
def artifacts():
    return stats.collect(['source_ip', 'destination_ip', 'destination_port', 'network_protocol'])
def entity(event):
    return {'derived': False, 'value': event['source_ip'], 'type': 'ip'}