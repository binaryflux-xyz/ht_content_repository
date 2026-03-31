def window():
    return None

def groupby():
    return None

def algorithm(event):
    if str(event.get('event_id')) == '4624':
        if event.get('logon_type') == '3' and not event.get('source_ip'):
            return 0.75
    return 0.0

def criticality():
    return 'HIGH'

def context(event):
    return (
        "Suspicious Kerberos service ticket usage detected for user " +
        str(event.get('source_account_name')) +
        " which may indicate Silver Ticket abuse."
    )

def tactic():
    return 'Persistence (TA0003)'

def technique():
    return 'Silver Ticket (T1558.002)'

def artifacts():
    return stats.collect([
        'source_account_name',
        'source_ip',
        'event_id'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('source_account_name'),
        'type': 'accountname'
    }