# Detection: Unauthorized Admin Group Change
# Purpose: Detect unauthorized addition or removal of members in Admin or Domain Admins groups.
# MITRE: Account Manipulation (TA1098) / Privilege Escalation (TA0004) / Persistence (TA0003)

def window():
    # Monitor over a short window to catch rapid changes
    return '5m'

def groupby():
    # Group per domain, actor, and target group
    return ['domain', 'account_name', 'target_group_name']

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
  
def algorithm(event):
    """
    Fires when Event ID 4728 or 4729 occurs on Admin or Domain Admins groups
    and the modifying user is not an authorized admin.
    """

    group_name = (
        event.get('target_group_name')
        or event.get('group_name')
        or ""
    )
    actor = event.get('account_name')
    host = event.get('host')
    evtid = int(event.get('event_id'))
    group_upper = group_name.upper()

    # Detect add/remove from admin groups
    if evtid not in [4728, 4729] or not group_name or 'ADMIN' not in group_upper:
        return 0.0


    # Known authorized admin accounts (adjust for environment)
    AUTHORIZED_ADMINS = ['SECADMIN', 'DOMAIN\\ADMINISTRATOR', 'SYSTEM', 'ITADMIN']

    if not actor:
        return 0.75

    actor_upper = actor.upper()

    # If the actor is in authorized list, ignore
    for adm in AUTHORIZED_ADMINS:
        if adm in actor_upper:
            return 0.0

    return 0.75


def context(event_data):
    actor = event.get('account_name')
    group_name = (
        event_data.get('target_group_name')
        or event_data.get('group_name')
        or "<unknown-group>"
    )
    evt_id = event_data.get('event_id')

    if str(evt_id) == "4728":
        action = "added a member to"
    elif str(evt_id) == "4729":
        action = "removed a member from"
    else:
        action = "modified"

    return (
        "Unauthorized admin group change detected: User %s %s the group %s without authorized admin privileges."
        % (actor, action, group_name)
    )


def criticality():
    return "HIGH"

def tactic():
    return "Privilege Escalation (TA0004)"

def technique():
    return "Account Manipulation (T1098)"

def artifacts():
    return stats.collect([
        "event_id",
        "account_name",
        "target_group_name",
        "host"
    ])

def entity(event):
    actor = event.get('account_name')
    return {"derived": False, "value": actor, "type": "accountname"}
