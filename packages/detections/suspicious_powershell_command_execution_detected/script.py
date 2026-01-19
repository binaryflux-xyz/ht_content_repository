def window():
    return None
def groupby():
    return None
def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
def algorithm(event):
    if event.get('event_id') == 4688:
        process_name = str(event.get('process_name') or '')
        if 'powershell.exe' in process_name.lower():  # case-insensitive
            suspicious_keywords = ['downloadstring', 'iex', 'invoke-expression', 'bypass']
            command_line = str(event.get('command_line') or '')
            for keyword in suspicious_keywords:
                if keyword.lower() in command_line.lower():
                    return 0.75
    return 0.0
def context(event_data):
    return "Suspicious PowerShell command executed: " + str(event_data.get('command_line') or '')

def criticality():
    return 'HIGH'
def tactic():
    return 'Execution (TA0002)'
def technique():
    return 'PowerShell (T1059/001)'
def artifacts():
    return stats.collect(['process_name', 'command_line'])
def entity(event):
    return {'derived': False, 'value': event.get('process_name'), 'type': 'process'}