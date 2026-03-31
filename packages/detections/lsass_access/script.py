def window():
    return None

def groupby():
    return None

def algorithm(event):
    proc = (event.get('process_name') or '').lower()

    if proc == 'lsass.exe':
        return 1.0

    return 0.0

def context(event):
    return "Access or execution involving LSASS detected on host " + str(event.get('host'))

def criticality():
    return 'CRITICAL'

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'OS Credential Dumping (T1003)'

def artifacts():
    return stats.collect(['process_name','host'])

def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}