def window():
    return None

def groupby():
    return None


def investigate():
    return "fortigate_session_analyser"
  
def automate():
    return True

def algorithm(event):  
    subtype = event.get("log_subtype")
    msg = event.get("event_details")
    srcintf = event.get("source_device_interface")
    dstintf = event.get("destination_device_interface")
    action = event.get("event_action")
    policy_name = event.get("policy_name")
  
    if subtype == "system" and "policy" in msg:
        if "allow all" in msg or (srcintf == "any" and dstintf == "any" and action =="accept"):
            return 1.0
    return 0.0


def context(event_data):
    # Safely extract relevant FortiGate log values with defaults
    policy_id = event_data.get('policy_id')
    policy_name = event_data.get('policy_name')
    action = event_data.get('event_action') 
    src_intf = event_data.get('source_device_interface')
    dst_intf = event_data.get('destination_device_interface')
    device = event_data.get('source_device_name')
    # Build the narrative
    message = (
        "At device {device} reported a configuration change "
        "The system log indicates a firewall policy modification: '{policy_name}' (ID: {policy_id}). "
        "The rule allows traffic from {src_intf} to {dst_intf} with the action set to '{action}'. "
        "This configuration effectively permits unrestricted network access, which may represent "
        "a misconfiguration or deliberate tampering with security controls. "
        "Such an 'allow-all' policy can expose the network to unauthorized access or lateral movement."
    ).format(
        event_time=event_time,
        device=device,
        admin_user=admin_user,
        policy_name=policy_name,
        policy_id=policy_id,
        src_intf=src_intf,
        dst_intf=dst_intf,
        action=action,
        msg=msg
    )
    return message

def criticality():
    return 'CRITICAL'

def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Impair Defenses (T1562)'

def artifacts():
    return stats.collect(['policy_id', 'source_device_interface', 'destination_device_interface', 'log_subtype', 'source_ip', 'destination_ip'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}