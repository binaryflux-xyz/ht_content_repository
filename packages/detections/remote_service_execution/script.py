def window():
    return None

def groupby():
    return None

def algorithm(event):
    if str(event.get('event_id')) == '7045':
        return 0.75
    return 0.0

def criticality():
    return 'HIGH'

def context(event):
    return (
        "A new service was created on host " +
        str(event.get('host')) +
        ", which may indicate remote execution."
    )

def tactic():
    return 'Lateral Movement (TA0008)'

def technique():
    return 'Remote Services (T1021)'

def artifacts():
    return stats.collect([
        'host',
        'source_account_name',
        'event_id'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('host'),
        'type': 'host'
    }