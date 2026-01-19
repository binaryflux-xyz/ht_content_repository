def window():
    return None

def groupby():
    return ['source_account_name']  # Group by user account

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
  
def algorithm(event):
    key = application.get("high_risk_pri")

    # If key is already set, always return 0.0
    if key is True:
        return 0.0
      
    # Ensure it's Event ID 4672 (Special Logon)
    if event.get('event_id') != 4672:
        return 0.0  # Ignore other events

    # Extract key fields
    user = event.get("source_account_name", "").lower()
    privileges = [priv.lower() for priv in event.get("privileges", [])]

    # List of known system accounts to ignore
    ignored_accounts = ["system", "local service", "network service", "administrator","SANAKA$"]

    # List of high-risk privileges
    critical_privileges = [
        "sedebugprivilege",
        "seimpersonateprivilege",
        "setakeownershipprivilege",
        "seloaddriverprivilege"
    ]

    # Ignore known system accounts
    if user in ignored_accounts:
        return 0.0  # Ignore system accounts

    # Only trigger if high-risk privileges are assigned
    if any(priv in privileges for priv in critical_privileges):
        application.put("high_risk_pri", True, 86400)
        return 0.75
    return 0.0

  
def context(event_data):
    base = (
        "High-risk admin privileges were assigned to user '{user}' "
        "from domain '{domain}' on device '{host}'.\n\n"
        "Privileges: {privileges}\n"
    ).format(
        user=event_data.get('source_account_name', 'Unknown'),
        domain=event_data.get('source_account_domain', 'Unknown'),
        host=event_data.get('host', 'Unknown'),
        privileges=", ".join(event_data.get('privileges', []))
    )

    return base

  
def criticality():
    return 'HIGH'
      
def tactic():
    return 'Privilege Escalation (TA0004)'
  
def technique():
    return "Access Token Manipulation (T1134)"
  
def artifacts():
    return stats.collect(['host', 'source_account_name', "privileges","source_account_domain"])
  
def entity(event):
    return {'derived': False, 'value': event.get('source_account_name'), 'type': 'accountname'}