
def window():
    return '5m'

def groupby():
    # Group by host and user to track per-user access attempts
    return ['host', 'account_name']
def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
def algorithm(event):

    evt_id = int(event.get('event_id'))
    user = event.get('account_name') 
    object_name = (event.get('object_name') or event.get('file_path') or "").lower()

    # Only consider event 4663 (Object Access)
    if evt_id != 4663 or not any(word in object_name for word in ['finance', 'hr']) :
        return 0.0

    
    user_lower = user.lower()
    is_hr_user = 'hr' in user_lower
    is_finance_user = 'finance' in user_lower

    # If user accessing HR files is not HR, or user accessing Finance files is not Finance
    if ('hr' in object_name and not is_hr_user) or ('finance' in object_name and not is_finance_user):
        stats.count("sensitive_folder_access_violation")

        # Trigger detection if any violation observed
        if stats.getcount("sensitive_folder_access_violation") >= 1:
            return 0.75

    return 0.0


def context(event_data):
    user = event_data.get('account_name') 
    object_name = (event_data.get('object_name') or event_data.get('file_path') or "<unknown-object>")
    host = event_data.get('host') 

    return (
        "Sensitive folder access detected on host %s by user %s. "
        "The user attempted to access a restricted HR or Finance folder (%s) outside their department."
        % (host, user, object_name)
    )


def criticality():
    return "HIGH"


def tactic():
    return "Collection (TA0009)"


def technique():
    return "Data from Information Repositories (T1213)"


def artifacts():
    # Relevant fields for investigation
    return stats.collect([
        "host",
        "account_name",
        "object_name",
        "file_path",
        "access_mask",
        "accesses"
    ])


def entity(event):
    actor = event.get('account_name')
    return {"derived": False, "value": actor, "type": "accountname"}
