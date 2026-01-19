# Detection: Printer Configuration Modified
# Purpose: Detect unexpected printer driver or configuration changes (Event ID 805 or 808) by non-admin users.
# Events: 805, 808
# Condition: 805 or 808 performed by a user not in the authorized admin list
# MITRE: Create or Modify System Process (T1543) / Persistence (TA0003)

def window():
    return '1m'  

def groupby():
    return ['host', 'source_account_name']
def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
def algorithm(event):
    # Normalize event id (use 0 if missing)
    evt_id = event.get('event_id')

    # Only care about printer config events 805 or 808
    if evt_id not in [805, 808]:
        return 0.0

    # Extract actor and host fields
    actor = event.get('source_account_name')
    host = event.get('host')

    # If actor missing, treat as suspicious
    if not actor:
        stats.count("printer_config_nonadmin")
        if stats.getcount("printer_config_nonadmin") > 0:
            return 0.75
        return 0.0

    # Define authorized admin tokens/identities (adjust to your environment)
    AUTH_ADMINS = ['ADMIN', 'DOMAIN\\ADMINISTRATOR', 'SYSTEM', 'PRINTADMIN', 'ITADMIN', 'SERVICE']

    actor_up = actor.upper()

    # If actor matches any authorized token substring, do not alert
    for tok in AUTH_ADMINS:
        if tok in actor_up:
            return 0.0

    # Otherwise count and alert
    stat_key = "printer_config_nonadmin"
    stats.count(stat_key)
    if stats.getcount(stat_key) > 0:
        return 0.75

    return 0.0

def context(event_data):
    actor = event.get('source_account_name')
    host = event.get('host')
    evt = event_data.get('event_id')

    return "Printer configuration change event (Event ID %s) detected on host %s performed by user %s who is not an authorized administrator." % (evt, host, actor)

def criticality():
    return "HIGH"

def tactic():
    return "Persistence (TA0003)"

def technique():
    return "Create or Modify System Process (T1543)"

def artifacts():
    return stats.collect([
        "event_id",
        "host",
        "source_account_name",
        "subject_user",
        "process_name"
    ])

def entity(event):
    actor = event.get('source_account_name')
    return {"derived": False, "value": actor, "type": "accountname"}
