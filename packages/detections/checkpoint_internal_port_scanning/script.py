#🔐 Detection 1: Port Scanning Behavior (Internal Reconnaissance)

def window():
    return '5m'

def groupby():
    return ['source_ip']


def algorithm(event):
    if event.get('event_action') == 'Accept' and event.get('network_protocol') in ['TCP', 'UDP']:
        if event.get('source_device_interface') == 'Internal' and event.get('destination_device_interface') == 'Internal':
            if stats.count_distinct(event.get('destination_port')) >= 10:
                return 0.75
    return 0.0

  
def context(event_data):
    return (
        "Internal port scanning behavior detected: host " +
        event_data.get('source_ip', 'unknown') +
        " attempted connections to " +
        str(stats.count_distinct('destination_port')) +
        " unique ports on internal systems within a 5-minute window."
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Discovery (TA0007)'

def technique():
    return 'Port Scanning (T1046)'

def artifacts():
    return stats.collect(['source_ip', 'destination_ip', 'destination_port', 'network_protocol'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ip'}