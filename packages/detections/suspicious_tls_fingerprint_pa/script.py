def window():
    return '5m'


def groupby():
    return ['source_ip']


def algorithm(event):
    source_ip = event.get('source_ip')
    if not source_ip:
        return 0.0

    fingerprint_text = ' '.join([
        str(event.get('network_encryption') or ''),
        str(event.get('event_details') or ''),
        str(event.get('event_alert') or ''),
        str(event.get('threat_name') or ''),
        str(event.get('applicationname') or ''),
        str(event.get('user_agent') or '')
    ]).lower()

    keywords = [
        'ja3',
        'ja4',
        'fingerprint',
        'tls fingerprint',
        'self-signed',
        'sni mismatch',
        'unknown tls',
        'certificate mismatch'
    ]

    if any(keyword in fingerprint_text for keyword in keywords):
        return 0.75

    if event.get('network_encryption') and 'unknown' in fingerprint_text:
        return 0.75

    return 0.0


def context(event_data):
    return (
        'Suspicious TLS fingerprint detected from source IP '
        + str(event_data.get('source_ip'))
        + '. The TLS handshake or certificate pattern appears unusual and may indicate evasion or proxying.'
    )


def criticality():
    return 'HIGH'


def tactic():
    return 'Defense Evasion (TA0005)'


def technique():
    return 'Protocol Tunneling (T1572)'


def artifacts():
    return stats.collect([
        'source_ip',
        'destination_ip',
        'destination_port',
        'network_encryption',
        'applicationname',
        'event_details',
        'event_alert',
        'threat_name',
        'user_agent'
    ])


def entity(event):
    return {
        'derived': False,
        'value': event.get('source_ip'),
        'type': 'ipaddress'
    }
