def window():
    return None

def groupby():
    return None

# def automate():
#     return True

def algorithm(event):  
    subtype = event.get("log_subtype")
    msg = event.get("event_details")

    if not subtype or not msg:
        return 0.0
      
    # List of keywords/phrases to look for
    keywords = ["FortiGate restarted", "service crash"]

    # Trigger if subtype is "system" and ANY keyword appears in the log message
    if subtype == "system" and any(k.lower() in msg for k in keywords):
        return 1.0
    return 0.0


def context(event_data):
    # Safely extract relevant FortiGate log values with defaults
    device = event_data.get('source_device_name')
    src_ip = event_data.get('source_ip')

    # Build the narrative
    message = (
        "The device {device} reported an unexpected service restart or crash event on source ip {src_ip}. "
        "Such behavior may result from system instability, misconfiguration, or a potential "
        "denial-of-service attempt targeting the firewall. "
        "If this event was not part of planned maintenance, it may represent deliberate "
        "interference with security defenses intended to cause downtime or bypass inspection."
    ).format(
        device=device,
        src_ip=src_ip
    )

    return message

def criticality():
    return 'CRITICAL'

def tactic():
    return 'Impact (TA0040)'

def technique():
    return 'Service Stop (T1489)'

def artifacts():
    return stats.collect(['policy_id', 'source_ip','destination_ip', 'source_device_name'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}