def window():
    return None

def groupby():
    return None

def algorithm(event):
    if str(event.get('event_id')) == '4719':
        return 0.75
    return 0.0

def criticality():
    return 'HIGH'

def context(event):
    return (
        "Audit policy was modified on host " +
        str(event.get('host')) +
        " by user " +
        str(event.get('source_account_name')) +
        "."
    )

def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Impair Defenses (T1562)'

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