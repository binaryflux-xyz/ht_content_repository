def window():
    return '30m'

def groupby():
    return ['user']

def algorithm(event):
    
    key = application.get("sudo_command")
    if key is True:
        return 0.0
      
    if event.get('process_name') == 'sudo' and 'root : PWD=/root' in event.get('event_details'):
        if stats.count('sudo_command') > 3:
            application.put("sudo_command", True, 86400)
            stats.resetcount('sudo_command')
            return 0.50
    return 0.0

def context(event_data):
    return "Root Directory was accessed using the sudo permissions for the user_ip " + event_data.get('user_ip')

def criticality():
    return 'MEDIUM'

def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Obfuscated Files or Information (T1027)'

def artifacts():
    return stats.collect(['host', 'process_name', 'event_action'])

def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'hostname'}