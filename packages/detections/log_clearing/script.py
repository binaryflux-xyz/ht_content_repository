def window():
    return None

def groupby():
    return None

def algorithm(event):
    if str(event.get('event_id')) == '1102':
        return 1.0
    return 0.0

def criticality():
    return 'CRITICAL'

def context(event):
    return (
        "Security logs were cleared on host " +
        str(event.get('host')) +
        ". This may indicate defense evasion."
    )

def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Indicator Removal on Host (T1070)'

def artifacts():
    return stats.collect([
        'host',
        'event_id',
        'source_account_name'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('host'),
        'type': 'host'
    }