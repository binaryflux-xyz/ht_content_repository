def window():
    return None

def groupby():
    return None

def algorithm(event):
    proc = (event.get('process_name') or '').lower()

    if proc in ['tasklist.exe','wmic.exe']:
        return 0.50

    return 0.0

def context(event):
    return "Process enumeration detected via " + str(event.get('process_name'))

def criticality():
    return 'MEDIUM'

def tactic():
    return 'Discovery (TA0007)'

def technique():
    return 'Process Discovery (T1057)'

def artifacts():
    return stats.collect(['process_name','host'])

def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}