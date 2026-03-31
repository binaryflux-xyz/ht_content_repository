def window():
    return None

def groupby():
    return None

def algorithm(event):
    if str(event.get('event_id')) == '4769':
        user = event.get('source_account_name')

        # ignore machine accounts
        if user and user.endswith('$'):
            return 0.0

        if stats.count('tgs_requests') > 20:
            stats.resetcount('tgs_requests')
            return 0.75

    return 0.0

def criticality():
    return 'HIGH'

def context(event):
    return (
        "Suspicious Kerberos ticket activity detected for user " +
        str(event.get('source_account_name')) +
        " which may indicate Golden Ticket usage."
    )

def tactic():
    return 'Persistence (TA0003)'

def technique():
    return 'Golden Ticket (T1558.001)'

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
