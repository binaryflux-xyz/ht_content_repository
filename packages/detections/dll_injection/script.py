def window():
    return None

def groupby():
    return None

def algorithm(event):
    path = (event.get('file_path') or '').lower()

    if '.dll' in path and 'temp' in path:
        return 0.75

    return 0.0

def context(event):
    return "Suspicious DLL execution from path " + str(event.get('file_path'))

def criticality():
    return 'HIGH'

def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Process Injection (T1055)'

def artifacts():
    return stats.collect(['file_path','process_name','host'])

def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}