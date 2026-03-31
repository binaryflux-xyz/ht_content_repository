def window():
    return None

def groupby():
    return None

def algorithm(event):
    proc = (event.get('process_name') or '').lower()

    if 'schtasks.exe' in proc:
        return 0.75

    return 0.0

def context(event):
    return "Scheduled task creation detected via " + str(event.get('process_name'))

def criticality():
    return 'HIGH'

def tactic():
    return 'Persistence (TA0003)'

def technique():
    return 'Scheduled Task/Job (T1053)'

def artifacts():
    return stats.collect(['process_name','host'])

def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}