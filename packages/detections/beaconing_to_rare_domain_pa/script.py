from datetime import datetime

def _is_internal_ip(ip):
    if not ip:
        return False
    return ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.')


def init(event):
    label = 'pa_beaconing_domain'
    source = event.get('source_ip')
    timestamp = int(event.get('eventreceivedtime') or event.get('timestamp') or 0)

    beacon_clusters = stats.beaconing(label, source, '1m', timestamp)
    features = {
        'domain': event.get('destination_hostname') or event.get('url'),
        'source_ip': source
    }
    rarity_clusters = stats.rarity('domain', features, 2)

    session.set('beacon_clusters', beacon_clusters)
    session.set('rarity_clusters', rarity_clusters)

    return 'Initialized beaconing_to_rare_domain detection'


def window():
    return '30d'


def groupby():
    return ['source_ip']


def algorithm(event):
    beacon = session.get('beacon_clusters')
    rarity = session.get('rarity_clusters')

    if not beacon or not rarity:
        return 0.0

    dst_ip = event.get('destination_ip')
    domain = event.get('destination_hostname') or event.get('url')

    if not domain:
        return 0.0

    if _is_internal_ip(dst_ip):
        return 0.0

    if not beacon.get('detected'):
        return 0.0

    total = 0
    anomalies = 0

    for entry in rarity:
        records = entry.get('records', [])
        total += len(records)
        anomalies += sum(1 for r in records if r.get('anomaly'))

    if total == 0:
        return 0.0

    rarity_score = anomalies / float(total)

    if rarity_score > 0:
        return 0.75

    return 0.0


def clusters(event):
    return {
        'beacon': session.get('beacon_clusters'),
        'rarity': session.get('rarity_clusters')
    }


def context(event_data):
    return (
        'Periodic outbound communication detected from source IP '
        + str(event_data.get('source_ip'))
        + ' to a rare external domain '
        + str(event_data.get('destination_hostname') or event_data.get('url'))
        + '. This behavior is highly indicative of command-and-control beaconing activity.'
    )


def criticality():
    return 'HIGH'


def tactic():
    return 'Command and Control (TA0011)'


def technique():
    return 'Application Layer Protocol (T1071)'


def artifacts():
    return stats.collect([
        'source_ip',
        'destination_ip',
        'destination_hostname',
        'destination_port',
        'network_protocol',
        'action',
        'applicationname'
    ])


def entity(event):
    return {
        'derived': False,
        'value': event.get('source_ip'),
        'type': 'ipaddress'
    }
