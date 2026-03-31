def window():
    return None


def groupby():
    return None


def investigate():
    return 'paloalto_session_analyser'


def automate():
    return True


def algorithm(event):
    dst_ip = event.get('destination_ip')
    action = (event.get('action') or event.get('event_action') or '').lower()

    if not dst_ip:
        return 0.0

    malicious_ip = tpi.query('MaliciousIP', 'ip = ?', [dst_ip])

    if not malicious_ip or not malicious_ip.get('rows'):
        return 0.0

    if action in ['allow', 'accept', 'permit']:
        return 0.75

    return 0.0


def context(event_data):
    return (
        'Outbound connection detected from source IP '
        + str(event_data.get('source_ip'))
        + ' to known malicious IP '
        + str(event_data.get('destination_ip'))
        + '. This communication was allowed and may indicate command-and-control activity.'
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
        'network_protocol',
        'applicationname',
        'action'
    ])


def entity(event):
    return {
        'derived': False,
        'value': event.get('source_ip'),
        'type': 'ipaddress'
    }
