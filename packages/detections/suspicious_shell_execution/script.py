def window():
    return None

def groupby():
    return None

def algorithm(event):
    process = (event.get('process_name') or '').lower()
    command = (event.get('process_command') or '').lower()
    parent = (event.get('parent_process_name') or '').lower()

    # Only shell processes
    shell_processes = ['bash', 'sh', 'zsh', 'ksh']

    if process not in shell_processes:
        return 0.0

    if any(x in command for x in ['-i', 'bash -i', 'sh -i']):
        return 0.75

    if any(x in command for x in ['-c', 'bash -c', 'sh -c']):
        return 0.75

    # Reverse shell indicators
    if any(x in command for x in ['/dev/tcp/', '>&', '0>&1', 'exec bash']):
        return 0.75

    suspicious_parents = ['python', 'perl', 'nc', 'netcat', 'java', 'php']

    if any(p in parent for p in suspicious_parents):
        return 0.75

    return 0.0

def context(event_data):
    return (
        "Suspicious shell execution detected on host " + str(event_data.get('host')) +
        ". Shell process '" + str(event_data.get('process_name')) +
        "' executed command: " + str(event_data.get('process_command')) +
        ". This may indicate attacker command execution or reverse shell activity."
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Execution (TA0002)'

def technique():
    return 'Command and Scripting Interpreter (T1059)'

def artifacts():
    return stats.collect([
        'host',
        'process_name',
        'process_command'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('host'),
        'type': 'host'
    }