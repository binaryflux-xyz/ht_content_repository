def window():
    return '5m'

def groupby():
    return ['source_ip', 'source_account_name']

def algorithm(event):
    message = (event.get('Message') or '').lower()
    event_type = event.get('event_type')

    if event_type == 'AUDIT_FAILURE' and 'login failed' in message:
        if stats.count('db_login_fail') >= 5:
            stats.resetcount('db_login_fail')
            return 0.75

    return 0.0

def context(event_data):
    return (
        "Multiple failed database login attempts detected for user " +
        str(event_data.get('source_account_name')) +
        " from source IP " + str(event_data.get('source_ip')) +
        ". This may indicate a brute-force attack against database authentication."
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
        'source_account_name',
        'event_type'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('source_account_name'),
        'type': 'user'
    }