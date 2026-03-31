def window():
    return '10m'

def groupby():
    return ['source_account_name']

def algorithm(event):
    if str(event.get('event_id')) == '4769':  # TGS request
        service = (event.get('service_name') or '').lower()
        
        # Ignore machine accounts
        if service.endswith('$'):
            return 0.0
        
        if stats.count('kerberoast') >= 10:
            stats.resetcount('kerberoast')
            return 0.75

    return 0.0

def criticality():
    return 'HIGH'

def context(event):
    return (
        "Multiple Kerberos service ticket requests detected from user " +
        str(event.get('source_account_name')) +
        ". This may indicate Kerberoasting activity."
    )

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'Kerberoasting (T1558.003)'

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