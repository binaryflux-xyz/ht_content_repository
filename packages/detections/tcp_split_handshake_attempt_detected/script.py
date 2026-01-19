def window():
    return None

def groupby():
    return ['source_ip']

def investigate():
    return "fortigate_session_analyser"
  
def automate():
    return True

def algorithm(event):
    alert = event.get('event_alert') == 'TCP.Split.Handshake'
    key = application.get("tcp_split")
    if key is True:
        return 0.0

    if alert and event.get('alert_score') == 10:
      application.put("tcp_split", True, 86400)
      return 0.50
    return 0.0


def context(event_data):
    details = event_data.get('event_details') or "a TCP split-handshake anomaly "
    src_ip = event_data.get('source_ip')
    src_port = event_data.get('source_port')
    dst_ip = event_data.get('destination_ip') 
    dst_port = event_data.get('destination_port')
    dest_country = event_data.get('destination_country')
    protocol = event_data.get('network_protocol')
    direction = event_data.get('network_direction')
    severity = event_data.get('alert_severity')
    device = event_data.get('source_device_name')

    return (
    "The firewall detected " + str(details) +
    " involving traffic from source " + str(src_ip) + ":" + str(src_port) +
    " to destination " + str(dst_ip) + ":" + str(dst_port) +
    ", indicating a destination in " + str(dest_country) +
    " and using the " + str(protocol) +
    " protocol in the " + str(direction) + " direction. "
    "The event was classified with a severity level of " + str(severity) +
    " on device " + str(device) + "."
)
def criticality():
    return 'MEDIUM'

def tactic():
    return 'Defense Evasion (TA0005)'

def technique():
    return 'Exploitation for Defense Evasion (T1211)'

def artifacts():
    return stats.collect(['source_ip', 'destination_ip', 'event_alert', 'event_action', 'network_protocol'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}
