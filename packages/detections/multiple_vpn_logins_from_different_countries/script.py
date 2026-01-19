def window():
    return '30m'

def groupby():
    return ['source_ip']


def automate():
    return False

def algorithm(event):  
    eventtype = event.get("event_type")
    action = event.get("event_action")

    if not eventtype or not action:
        return 0.0

    # Trigger if subtype is "system" and ANY keyword appears in the log message
    if eventtype!="vpn" and action!="login":
        return 0.0
      
    dest_country = stats.accumulate(['destination_country'])
    unique_country=len(dest_country.get("destination_country"))
    if unique_country == 2:
      return 1.0
    return 0.0


# def context(event_data):
#     return str(event_data.get('event_details')) + " from source ip " + str(event_data.get('source_ip')) + " and source port " + str(event_data.get('source_port')) + " to destination ip " + str(event_data.get('destination_ip')) + " and destination port " + str(event_data.get('destination_port'))
def context(event_data):
    # Safely extract relevant FortiGate VPN log values with defaults
    src_ip = event_data.get('source_ip')
    geo_country = event_data.get('destination_country')
    device = event_data.get('source_device_name')
    eventtype = event_data.get("event_type")
    action = event_data.get("event_action")

    # Build the narrative
    message = (
        "The device {device} observed multiple VPN login sessions "
        "from different geographic locations, including {geo_country} (source IP: {src_ip}). "
        "The event shows type {eventtype} with action {action}. "
        "This pattern may indicate credential sharing or potential account compromise, "
        "as simultaneous or rapid logins from distant regions are atypical for normal user behavior."
    ).format(
        device=device,
        geo_country=geo_country,
        src_ip=src_ip,
        eventtype=eventtype,
        action=action
      
    )

    return message

def criticality():
    return 'CRITICAL'

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'Valid Accounts (T1078)'

def artifacts():
    return stats.collect(['destination_country', 'source_ip','destination_ip'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}