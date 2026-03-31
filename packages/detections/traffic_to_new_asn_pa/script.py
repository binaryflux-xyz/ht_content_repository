def window():
    return None


def groupby():
    return ['source_ip']


def _is_internal_ip(ip):
    if not ip:
        return False
    return ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.')


def _extract_asn(dst_ip, event):
    asn = event.get('destination_asn') or event.get('asn')
    if asn:
        return str(asn)

    try:
        asn_data = tpi.query('ASN', 'ip = ?', [dst_ip])
        if asn_data and asn_data.get('rows'):
            first_row = asn_data.get('rows')[0]
            if isinstance(first_row, (list, tuple)):
                for value in first_row:
                    if value not in [None, '', '-', '_']:
                        return str(value)
            elif first_row not in [None, '', '-', '_']:
                return str(first_row)
    except Exception:
        pass

    return None


def algorithm(event):
    source_ip = event.get('source_ip')
    dst_ip = event.get('destination_ip')

    if not source_ip or not dst_ip:
        return 0.0

    if _is_internal_ip(dst_ip):
        return 0.0

    asn = _extract_asn(dst_ip, event)
    if not asn:
        return 0.0

    key = 'pa_seen_asn_%s_%s' % (source_ip, asn)
    if application.get(key):
        return 0.0

    application.put(key, True, 86400)
    return 0.75


def context(event_data):
    return (
        'Traffic from source IP '
        + str(event_data.get('source_ip'))
        + ' to destination IP '
        + str(event_data.get('destination_ip'))
        + ' was observed in a new ASN ('
        + str(event_data.get('destination_asn') or event_data.get('asn'))
        + '), which may indicate a new infrastructure or staging location.'
    )


def criticality():
    return 'MEDIUM'


def tactic():
    return 'Defense Evasion (TA0005)'


def technique():
    return 'Proxy (T1090)'


def artifacts():
    return stats.collect([
        'source_ip',
        'destination_ip',
        'destination_country',
        'network_protocol',
        'applicationname',
        'destination_asn',
        'asn'
    ])


def entity(event):
    return {
        'derived': False,
        'value': event.get('source_ip'),
        'type': 'ipaddress'
    }
