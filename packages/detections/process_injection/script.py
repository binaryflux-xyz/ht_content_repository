def window():
    return None

def groupby():
    return None

def algorithm(event):
    proc = (event.get('process_name') or '').lower()
    parent = (event.get('parent_process') or '').lower()

    if parent in ['powershell.exe','cmd.exe'] and proc in ['svchost.exe','explorer.exe']:
        return 0.75

    return 0.0

def context(event):
    return "Possible process injection: " + parent + " spawned " + proc

def criticality():
    return 'HIGH'

def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Process Injection (T1055)'

def artifacts():
    return stats.collect(['process_name','parent_process','host'])

def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}