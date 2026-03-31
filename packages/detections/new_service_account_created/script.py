def window():
    return None

def groupby():
    return None

def algorithm(event):
    if str(event.get('event_id')) == '4720':
        user = (event.get('destination_account_name') or '').lower()
        
        if 'svc' in user or 'service' in user:
            return 0.75

    return 0.0

def criticality():
    return 'HIGH'

def context(event):
    return (
        "New service account " +
        str(event.get('destination_account_name')) +
        " was created. This may indicate persistence setup."
    )

def tactic():
    return 'Persistence (TA0003)'

def technique():
    return 'Create Account (T1136)'

def artifacts():
    return stats.collect([
        'destination_account_name',
        'source_account_name',
        'event_id'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('destination_account_name'),
        'type': 'accountname'
    }