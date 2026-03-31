def window():
    return None

def groupby():
    return None

def algorithm(event):
    proc = (event.get('process_name') or '').lower()
    path = (event.get('file_path') or '').lower()

    if proc == 'powershell.exe' and not path:
        return 0.75

    return 0.0

def context(event):
    return "Possible reflective loading via PowerShell on host " + str(event.get('host'))

def criticality():
    return 'HIGH'

def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Reflective Code Loading (T1620)'

def artifacts():
    return stats.collect(['process_name','host'])

def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}