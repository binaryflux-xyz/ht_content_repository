# Detection: Audit Log Cleared
# Purpose: Detect Windows Security Audit Log clearing (Event ID 1102) by non-SECADMIN actor.
# MITRE: Indicator Removal (TA1070) / Defense Evasion (TA0005)

def window():
    # Immediate detection window (short scope)
    return '1m'

def groupby():
    # Group by host and actor for correlation
    return ['host', 'account_name']

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
  
def algorithm(event):
    actor = event.get('account_name')
    host = event.get('host')
    evtid = int(event.get('event_id'))

    # Check for Audit Log Cleared event
    if evtid != 1102:
        return 0.0

    SECADMINTOKENS = ['SECADMIN', 'SECURITYADMIN', 'SECURITY', 'AUDIT ADMIN']
   
    if not actor:
        return 0.75

    actor_upper = actor.upper()
    for tok in SECADMINTOKENS:
        if tok in actor_upper:
            return 0.0

    # Otherwise, flag as high severity
    return 0.75


def context(event_data):
    actor = event.get('account_name')
    host = event.get('host')

    return (
        "Audit Log Cleared event (Event ID 1102) detected on host %s by user %s who is not part of the SECADMIN group."
        % (host, actor)
    )


def criticality():
    return "HIGH"

def tactic():
    return "Defense Evasion (TA0005)"

def technique():
    return "Indicator Removal (TA1070)"

def artifacts():
    return stats.collect([
        "host",
       "account_name",
        "process_name"])

def entity(event):
    actor = event.get('account_name')
    return {"derived": False, "value": actor, "type": "accountname"}
