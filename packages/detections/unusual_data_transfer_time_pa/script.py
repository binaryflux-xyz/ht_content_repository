from datetime import datetime


def window():
    return '15m'


def groupby():
    return ['source_ip']


def _event_hour(event):
    ts = event.get('eventreceivedtime') or event.get('timestamp')
    if not ts:
        return None

    try:
        return datetime.utcfromtimestamp(int(ts) / 1000).hour
    except Exception:
        return None


def algorithm(event):
    timestamp = event.get('eventreceivedtime') or event.get('timestamp')
    bytes_out = event.get('network_bytes_out')

    if not timestamp or not bytes_out:
        return 0.0

    hour = _event_hour(event)
    if hour is None:
        return 0.0

    bytes_out = int(bytes_out)

    if bytes_out < 5000000:
        return 0.0

    if hour >= 22 or hour <= 6:
        return 0.75

    return 0.0


def context(event_data):
    return (
        'Unusual data transfer detected from source IP '
        + str(event_data.get('source_ip'))
        + ' to destination IP '
        + str(event_data.get('destination_ip'))
        + ' during off-hours. A total of '
        + str(event_data.get('network_bytes_out'))
        + ' bytes were transferred outside normal business hours.'
    )


def criticality():
    return 'HIGH'


def tactic():
    return 'Exfiltration (TA0010)'


def technique():
    return 'Exfiltration Over Network (T1041)'


def artifacts():
    return stats.collect([
        'source_ip',
        'destination_ip',
        'network_bytes_out',
        'destination_port',
        'network_protocol',
        'eventreceivedtime'
    ])


def entity(event):
    return {
        'derived': False,
        'value': event.get('source_ip'),
        'type': 'ipaddress'
    }
