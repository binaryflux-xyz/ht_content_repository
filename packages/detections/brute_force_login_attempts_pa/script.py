def window():
    return '5m'


def groupby():
    return ['source_ip']


def algorithm(event):
    message = ' '.join([
        str(event.get('event_details') or ''),
        str(event.get('event_message') or ''),
        str(event.get('descriptions') or ''),
        str(event.get('message') or '')
    ]).lower()
    src_ip = event.get('source_ip')

    if not message or not src_ip:
        return 0.0

    if any(indicator in message for indicator in [
        'login failed',
        'authentication failed',
        'invalid user',
        'failed password',
        'bad credentials'
    ]):
        count = stats.count('failed_login_attempts')
        if count >= 5:
            stats.resetcount('failed_login_attempts')
            return 0.75

    return 0.0


def context(event_data):
    return (
        'Multiple failed login attempts detected from source IP '
        + str(event_data.get('source_ip'))
        + ' within a short time window. This pattern indicates a possible brute-force attack '
        + 'attempting to gain unauthorized access.'
    )


def criticality():
    return 'HIGH'


def tactic():
    return 'Credential Access (TA0006)'


def technique():
    return 'Brute Force (T1110)'


def artifacts():
    return stats.collect([
        'source_ip',
        'event_details',
        'event_message',
        'descriptions',
        'destination_ip',
        'destination_port'
    ])


def entity(event):
    return {
        'derived': False,
        'value': event.get('source_ip'),
        'type': 'ipaddress'
    }
