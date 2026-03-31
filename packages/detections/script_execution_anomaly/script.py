def window():
    return None

def groupby():
    return None

def algorithm(event):
    proc = (event.get('process_name') or '').lower()
    url = (event.get('url') or '').lower()

    if proc == 'powershell.exe' and url:
        return 0.75

    return 0.0

def context(event):
    return (
        "PowerShell executed with network interaction via URL " +
        str(event.get('url')) +
        " on host " + str(event.get('host'))
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Execution (TA0002)'

def technique():
    return 'Command and Scripting Interpreter (T1059)'

def artifacts():
    return stats.collect(['process_name','url','host'])

def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}