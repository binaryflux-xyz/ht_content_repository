def window():
    return None

def groupby():
    return None

def algorithm(event):
    proc = (event.get('process_name') or '').lower()

    if proc in ['procdump.exe', 'mimikatz.exe', 'lsass.exe']:
        return 1.0

    return 0.0

def criticality():
    return 'CRITICAL'
def context(event):
    return (
        "Suspicious process " + str(event.get('process_name')) +
        " detected which may indicate credential dumping activity."
    )

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'OS Credential Dumping (T1003)'

def artifacts():
    return stats.collect([
        'host',
        'process_name',
        'process_id'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('host'),
        'type': 'host'
    }