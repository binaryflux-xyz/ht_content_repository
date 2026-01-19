def window():
    return '10m'

def groupby():
    return ['source_ip']

def investigate():
    return "fortigate_session_analyser"
  
def automate():
    return True

def algorithm(event):  
    srcintf = event.get("source_device_interface")
    dstintf = event.get("destination_device_interface")

    # Trigger if subtype is "system" and ANY keyword appears in the log message
    if srcintf!="internal" and dstintf!="internal":
        return 0.0
      
    dest_ip = stats.accumulate(['destination_ip'])
    unique_country=len(dest_ip.get("destination_ip"))
    if unique_country > 10:
      return 0.75
    return 0.0


def context(event_data):
    # Safely extract relevant FortiGate log values with defaults
    src_ip = event_data.get('source_ip')
    dst_ip = event_data.get('destination_ip')
    src_intf = event_data.get('source_device_interface')
    dst_intf = event_data.get('destination_device_interface')
    device = event_data.get('source_device_name') 
    proto = event_data.get('network_protocol') 

    # Build the narrative
    message = (
        "The device {device} detected on source {src_ip} communicating with several internal systems "
        "across interface {src_intf} targeting {dst_intf} using protocol {proto}. "
        "This pattern suggests potential lateral movement or network reconnaissance, "
        "as a single internal host establishing multiple internal connections in a short period is unusual."
    ).format(
        device=device,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_intf=src_intf,
        dst_intf=dst_intf,
        proto=proto
    )

    return message

def criticality():
    return 'HIGH'

def tactic():
    return 'Lateral Movement (TA0008)'

def technique():
    return 'Lateral Tool Transfer (T1021)'

def artifacts():
    return stats.collect(['destination_device_interface', 'source_ip','destination_ip', 'source_device_interface'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}