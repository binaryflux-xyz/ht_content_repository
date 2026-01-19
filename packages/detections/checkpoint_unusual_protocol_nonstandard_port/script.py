def window():
    return None
def groupby():
    return None
def algorithm(event):
    if event['network_protocol'] == 'HTTP' and int(event['destination_port']) not in [80, 8080, 443]:
        return 0.75
    return 0.0
def context(event_data):
    return (
        "HTTP traffic detected over non-standard port "
        + str(event_data['destination_port'])
        + " from " + event_data['source_ip']
        + " to " + event_data['destination_ip'] + "."
    )
def criticality():
    return 'HIGH'
def tactic():
    return 'Command and Control (TA0011)'
def technique():
    return 'Application Layer Protocol (T1071.001)'
def artifacts():
    return stats.collect(['source_ip', 'destination_ip', 'destination_port', 'network_protocol'])
def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}