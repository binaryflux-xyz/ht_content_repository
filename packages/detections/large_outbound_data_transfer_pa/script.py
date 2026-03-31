def window():
    return '15m'


def groupby():
    return ['source_ip']


def _is_internal_ip(ip):
    if not ip:
        return False
    return ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.')


def algorithm(event):
    bytes_out = event.get('network_bytes_out')
    dst_ip = event.get('destination_ip')

    if not bytes_out or not dst_ip:
        return 0.0

    if _is_internal_ip(dst_ip):
        return 0.0

    if int(bytes_out) > 500000000:
        return 0.50

    return 0.0


def context(event):
    return (
        'Large outbound data transfer detected from source IP '
        + str(event.get('source_ip'))
        + ' to destination IP '
        + str(event.get('destination_ip'))
        + ' with total bytes sent '
        + str(event.get('network_bytes_out'))
        + '. This may indicate potential data exfiltration.'
    )


def criticality():
    return 'MEDIUM'


def tactic():
    return 'Exfiltration (TA0010)'


def technique():
    return 'Exfiltration Over Network (T1041)'


def artifacts():
    return stats.collect([
        'source_ip',
        'destination_ip',
        'network_bytes_out',
        'network_protocol',
        'applicationname'
    ])


def entity(event):
    return {
        'derived': False,
        'value': event.get('source_ip'),
        'type': 'ipaddress'
    }
