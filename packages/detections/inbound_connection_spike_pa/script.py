def window():
    return '5m'


def groupby():
    return ['destination_ip']


def algorithm(event):
    log_type = (event.get('event_type') or event.get('log_type') or '').lower()
    action = (event.get('action') or event.get('event_action') or '').lower()

    if log_type and log_type != 'traffic':
        return 0.0

    if action not in ['allow', 'accept', 'permit']:
        return 0.0

    count = stats.count('inbound_connections')
    if count >= 100:
        stats.resetcount('inbound_connections')
        return 0.75

    return 0.0


def context(event_data):
    return (
        'Spike in inbound connections detected targeting destination IP '
        + str(event_data.get('destination_ip'))
        + '. A high number of incoming connections were observed within a short time window, '
        + 'which may indicate scanning, brute-force attempts, or exploitation activity.'
    )


def criticality():
    return 'HIGH'


def tactic():
    return 'Initial Access (TA0001)'


def technique():
    return 'Exploit Public-Facing Application (T1190)'


def artifacts():
    return stats.collect([
        'source_ip',
        'destination_ip',
        'destination_port',
        'network_protocol',
        'action'
    ])


def entity(event):
    return {
        'derived': False,
        'value': event.get('destination_ip'),
        'type': 'ipaddress'
    }
