def window():
    return None

def groupby():
    return None

def algorithm(event):
    file_path = (event.get('file_path') or '').lower()
    command = (event.get('process_command') or '').lower()
    details = (event.get('event_details') or '').lower()
    uid = event.get('user_id')

    if uid and str(uid) != '0':
        if (
            '.ssh/id_rsa' in file_path or
            '.ssh/id_dsa' in file_path or
            '.ssh/id_ed25519' in file_path or
            '.ssh/id_rsa' in command or
            '.ssh/id_dsa' in command or
            '.ssh/id_ed25519' in command or
            '.ssh/id_rsa' in details or
            '.ssh/id_dsa' in details or
            '.ssh/id_ed25519' in details
        ):
            return 0.75

    return 0.0


def context(event_data):
    return (
        "Access to SSH private key file detected. "
        "UID " + str(event_data.get('user_id')) +
        " accessed " + str(event_data.get('file_path')) +
        " on host " + str(event_data.get('host')) +
        ". This may indicate credential theft or lateral movement preparation."
    )


def criticality():
    return 'HIGH'


def tactic():
    return 'Credential Access (TA0006)'


def technique():
    return 'Unsecured Credentials (T1552)'


def artifacts():
    return stats.collect(['host','user_id','process_name','file_path','event_details', 'process_command', 'executable'])


def entity(event):
    return {'derived': False, 'value': event.get('user_id'), 'type': 'userid'}