def window():
    return '1h'

def groupby():
    return ['user_name']

def investigate():
    return "fortigate_session_analyser"
  
def automate():
    return True

def algorithm(event):  
    action = event.get("event_action")
    alert = event.get("event")
    src_ip = event.get("source_ip")

    # Trigger if subtype is "system" and ANY keyword appears in the log message
    if action!="FSSO-logon" and alert!="FSSO logon authentication status":
        return 0.0
      
    ip = stats.accumulate(['source_ip'])
    unique_ip=len(ip.get('source_ip'))
    if unique_ip > 5:
      stats.dissipate(['source_ip'])
      return 0.75
    return 0.0


def context(event_data):
    user = event_data.get('user_name')
    src_ip = event_data.get('source_ip')
    device = event_data.get('source_device_name') 
    action = event_data.get("event_action")

    # Build the narrative
    message = (
        "User {user} authenticated via {action} from source IP {src_ip} on device {device}. "
        "This account has logged in from more than 5 distinct IP addresses within the 1 hour. "
        "Such multi-IP activity is unusual for a single user and may indicate credential compromise, "
    ).format(
        user=user,
        src_ip=src_ip,
        device=device,
        action=action,
    )

    return message

def criticality():
    return 'HIGH'

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'Valid Accounts (T1078)'

def artifacts():
    return stats.collect(['user_name', 'source_ip','event_action', 'source_device_name'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}