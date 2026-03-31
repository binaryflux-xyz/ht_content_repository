def window():
    return '5m'

def groupby():
    return ['source_ip']

def algorithm(event):
    if str(event.get('event_id')) == '4625':
        if stats.count('spray') >= 10:
            stats.resetcount('spray')
            return 0.75
    return 0.0

def criticality():
    return 'HIGH'

def context(event):
    return (
        "Multiple failed login attempts detected from source IP " +
        str(event.get('source_ip')) +
        " across multiple accounts, indicating possible password spraying."
    )

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'Password Spraying (T1110.003)'

def artifacts():
    return stats.collect([
        'source_ip',
        'event_id',
        'source_account_name'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('source_ip'),
        'type': 'ipaddress'
    }