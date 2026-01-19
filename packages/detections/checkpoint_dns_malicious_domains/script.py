def window():
    return None
def groupby():
    return None
def algorithm(event):
    if event['event_type'] == 'DNS' and event['query_name'] in tpi.malicious_domains():
        return 1.0
    return 0.0
def context(event_data):
    return (
        "DNS query to known malicious domain "
        + event_data['query_name'] + " from internal host "
        + event_data['source_ip'] + "."
    )
def criticality():
    return 'CRITICAL'
def tactic():
    return 'Command and Control (TA0011)'
def technique():
    return 'Domain Generation Algorithms (T1568.002)'
def artifacts():
    return stats.collect(['source_ip', 'query_name', 'dns_type', 'dns_response'])
def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}