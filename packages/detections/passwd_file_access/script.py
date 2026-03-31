def window():
    return None

def groupby():
    return None

def algorithm(event):
    file_path = (event.get('file_path') or '').lower()
    command = (event.get('process_command') or '').lower()
    process = (event.get('process_name') or '').lower()
    user = str(event.get('user_id') or '')

    # Target file
    if '/etc/passwd' not in file_path and '/etc/passwd' not in command:
        return 0.0

    # Ignore root/system access (expected behavior)
    if user == '0':
        return 0.0

    # Suspicious access via tools
    suspicious_tools = [
        'cat', 'cp', 'scp', 'rsync', 'wget', 'curl',
        'base64', 'tar', 'gzip'
    ]

    if any(tool in command for tool in suspicious_tools):
        return 0.75

    # Access via unusual process
    if process not in ['login', 'sshd', 'systemd', 'useradd', 'usermod']:
        return 0.75

    return 0.0

def context(event_data):
    return (
        "Suspicious access to /etc/passwd detected on host " + str(event_data.get('host')) +
        " by process " + str(event_data.get('process_name')) +
        " using command: " + str(event_data.get('process_command')) +
        ". This may indicate credential enumeration or preparation for further attacks."
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'Unsecured Credentials (T1552)'

def artifacts():
    return stats.collect([
        'host',
        'process_name',
        'file_path'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('host'),
        'type': 'host'
    }