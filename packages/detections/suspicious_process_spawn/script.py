def window():
    return None

def groupby():
    return None

def algorithm(event):
    proc = (event.get('process_name') or '').lower()
    parent = (event.get('parent_process') or '').lower()

    suspicious = ['powershell.exe','cmd.exe','wscript.exe','cscript.exe']

    if proc in suspicious and parent not in ['explorer.exe','services.exe']:
        return 0.75

    return 0.0

def context(event):
    return (
        "Suspicious process " + str(event.get('process_name')) +
        " spawned by " + str(event.get('parent_process')) +
        " on host " + str(event.get('host'))
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Execution (TA0002)'

def technique():
    return 'Command and Scripting Interpreter (T1059)'

def artifacts():
    return stats.collect(['process_name','parent_process','host'])

def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'host'}