def window():
    return None

def groupby():
    return None

def investigate():
    return "fortigate_session_analyser"
  
def automate():
    return True

def algorithm(event):  
    dst_port = event.get('destination_port')
    action = event.get('event_action')
    dstintfrole = event.get('destination_device_interface_role')
    protocol = event.get('network_protocol')

    # Trigger if type matches and destination IP is malicious
    if dst_port not in [80, 443, 53, 123, 25] and dstintfrole == 'wan' and action == 'accept' and protocol in ['HTTPS', 'DNS']:
        return 0.75
    return 0.0

def context(event_data):
    # Safely extract values with defaults
    action = event_data.get('event_action')
    src_ip = event_data.get('source_ip')
    src_port = event_data.get('source_port')
    dst_ip = event_data.get('destination_ip') 
    dst_port = event_data.get('destination_port') 
    app = event_data.get('applicationname') or event_data.get('network_protocol') 
    dst_role = event_data.get('destination_device_interface_role')
    src_dev = event_data.get('source_device_name') 
    policy = event_data.get('policy_name') 
    country = event_data.get('destination_country')

    message = (
        "The firewall recorded outbound network activity where traffic was {action} "
        "from {src_dev} ({src_ip}:{src_port}) to {dst_ip}:{dst_port} "
        "using {app}. The destination interface role was {dst_role}, and the "
        "policy applied was '{policy}'. The target IP belongs to {country}. "
        "This event was detected as external communication on a potentially uncommon port, "
        "which may indicate the use of custom or covert command-and-control channels."
    ).format(
        action=action,
        src_dev=src_dev,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        app=app,
        dst_role=dst_role,
        policy=policy,
        country=country
    )

    return message

def criticality():
    return 'HIGH'

def tactic():
    return 'Command and Control (TA0011)'



def technique():
    return 'Non-Standard Port (T1571)'

def artifacts():
    return stats.collect(['source_ip', 'destination_ip', 'destination_port', 'network_protocol', 'event_action', 'destination_device_interface_role'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}
