def window():
    return None

def groupby():
    return None

def algorithm(event):
    if str(event.get('event_id')) == '4662':
        if 'replication' in str(event.get('access_list_raw')).lower():
            return 1.0
    return 0.0

def criticality():
    return 'CRITICAL'

def context(event):
    return (
        "Directory replication request detected by user " +
        str(event.get('source_account_name')) +
        ". This may indicate a DCSync attack."
    )

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'DCSync (T1003.006)'

def artifacts():
    return stats.collect([
        'source_account_name',
        'access_list_raw',
        'event_id'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('source_account_name'),
        'type': 'accountname'
    }