import math
from collections import Counter


def window():
    return '10m'


def groupby():
    return ['source_ip']


def _shannon_entropy(value):
    if not value:
        return 0.0

    value = str(value)
    counts = Counter(value)
    length = len(value)

    entropy = 0.0
    for count in counts.values():
        p = float(count) / float(length)
        entropy -= p * math.log(p, 2)

    return entropy


def algorithm(event):
    source_ip = event.get('source_ip')
    domain = event.get('destination_hostname') or event.get('host') or event.get('url')
    proto = (event.get('network_protocol') or event.get('applicationname') or '').lower()
    details = ' '.join([
        str(event.get('event_details') or ''),
        str(event.get('message') or ''),
        str(event.get('descriptions') or ''),
        str(event.get('log_type') or '')
    ]).lower()

    if not source_ip or not domain:
        return 0.0

    if 'dns' not in proto and 'dns' not in details:
        return 0.0

    domain_entropy = _shannon_entropy(domain)
    if stats.count(source_ip) > 20 and domain_entropy > 3.8:
        return 1.0

    return 0.0


def context(event):
    return (
        'Suspicious DNS query activity detected from source IP '
        + str(event.get('source_ip'))
        + '. The system queried the domain '
        + str(event.get('destination_hostname') or event.get('host') or event.get('url'))
        + ', which has an unusually long length and high character entropy. '
        + 'This activity may indicate domain generation algorithm usage or DNS tunneling.'
    )


def criticality():
    return 'CRITICAL'


def tactic():
    return 'Command and Control (TA0011)'


def technique():
    return 'Application Layer Protocol (T1071)'


def artifacts():
    return stats.collect([
        'source_ip',
        'destination_ip',
        'destination_port',
        'destination_hostname',
        'host',
        'url',
        'network_protocol',
        'applicationname',
        'event_details',
        'message',
        'descriptions'
    ])


def entity(event):
    return {
        'derived': False,
        'value': event.get('source_ip'),
        'type': 'ipaddress'
    }
