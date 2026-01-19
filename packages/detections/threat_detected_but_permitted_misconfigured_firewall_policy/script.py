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
    action = event.get("event_action")


    if subtype in ("virus", "ips", "webfilter") and action=="allow":
        return 1.0
    return 0.0

def context(event_data):
    # Safely extract relevant FortiGate log values with defaults
    src_ip = event_data.get('source_ip')
    dst_ip = event_data.get('destination_ip')
    src_intf = event_data.get('source_device_interface')
    dst_intf = event_data.get('destination_device_interface')
    device = event_data.get('source_device_name')
    policy_id = event_data.get('policy_id')
    policy_name = event_data.get('policy_name')
    action = event_data.get('event_action')

    # Build the narrative
    message = (
        "The device {device} detected traffic originating from {src_ip} "
        "via interface {src_intf} and targeting {dst_ip} through interface {dst_intf}. "
        "The applied firewall policy '{policy_name}' (ID: {policy_id}) took the action '{action}', "
        "allowing the traffic to proceed. "
        "This behavior may indicate a misconfigured or overly permissive security policy, "
    ).format(
        device=device,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_intf=src_intf,
        dst_intf=dst_intf,
        policy_id=policy_id,
        policy_name=policy_name,
        action=action,
    )

    return message

def criticality():
    return 'CRITICAL'

def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Impair Defenses (T1562)'

def artifacts():
    return stats.collect(['policy_id', 'source_ip','destination_ip', 'log_subtype', 'event_action', 'source_device_name'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}