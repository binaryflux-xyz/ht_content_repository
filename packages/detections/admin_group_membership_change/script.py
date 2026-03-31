def window():
    return None

def groupby():
    return None

def algorithm(event):
    if str(event.get('event_id')) in ['4728','4732','4756']:
        return 0.75
    return 0.0

def criticality():
    return 'HIGH'

def context(event):
    return (
        "User " + str(event.get('destination_account_name')) +
        " was added to a privileged group by " +
        str(event.get('source_account_name')) +
        "."
    )

def tactic():
    return 'Privilege Escalation (TA0004)'

def technique():
    return 'Account Manipulation (T1098)'

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