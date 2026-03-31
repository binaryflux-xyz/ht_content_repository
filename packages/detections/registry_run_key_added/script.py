def window():
    return None

def groupby():
    return None

def algorithm(event):
    path = (event.get('file_path') or '').lower()

    if 'run' in path and 'registry' in path:
        return 0.75

    return 0.0

def context(event):
    return "Registry persistence detected via run key: " + str(event.get('file_path'))

def criticality():
    return 'HIGH'

def tactic():
    return 'Persistence (TA0003)'

def technique():
    return 'Registry Run Keys (T1547)'

def artifacts():
    return stats.collect(['file_path','process_name','host'])

def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}