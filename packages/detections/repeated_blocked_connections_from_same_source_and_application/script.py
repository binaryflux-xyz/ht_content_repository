def window():
    return None

def groupby():
    return ['source_ip', 'source_device_name']

def investigate():
    return "fortigate_session_analyser"
  
def automate():
    return True


# def algorithm(event):
#     src_ip = event.get('source_ip')
#     url = event.get('url')
#     key = application.get("blocked_events")

#     if key is True:
#         return 0.0
    
#     if not src_ip:
#         return 0.0
      
#     incidrrange=cidr.inRange(src_ip,["10.70.150.0/23","10.70.151.0/24","10.70.210.0/24","10.70.220.0/23", "10.70.222.0/24"])
#     if incidrrange:
#       return 0.0

#     if not url:
#         return 0.0

#     allowed_url = tpi.query("Whitelistedurls", "url = ?", [url])

#     if allowed_url or allowed_url.get('rows'):
#         return 0.0
      
#     allowed_url = [row[0] for row in allowed_url.get('rows', [])]
    
#     if event.get('event_action') == 'blocked' and event.get('log_type') == 'utm' and event.get('log_subtype') in ['ssl', 'webfilter'] and url not in allowed_url :
#         application.put("blocked_events", True, 86400)
#         return 0.75
#     return 0.0
def algorithm(event):
    src_ip = event.get('source_ip')
    url = event.get('url')
    key = application.get("blocked_events")

    if key is True:
        return 0.0
    
    if not src_ip:
        return 0.0
      
    incidrrange = cidr.inRange(src_ip, [
        "10.70.150.0/23",
        "10.70.151.0/24",
        "10.70.210.0/24",
        "10.70.220.0/23",
        "10.70.222.0/24"
    ])

    if incidrrange:
        return 0.0

    log_subtype = event.get('log_subtype')

    if log_subtype == 'webfilter':
        if not url:
            return 0.0

        allowed_url = tpi.query("Whitelistedurls", "url = ?", [url])
        rows = allowed_url.get('rows') if allowed_url else []

        if rows:
            return 0.0
        
        allowed_url = [row[0] for row in rows]

        if (
            event.get('event_action') == 'blocked'
            and event.get('log_type') == 'utm'
            and url not in allowed_url
        ):
            application.put("blocked_events", True, 86400)
            return 0.75

    if log_subtype == 'ssl':
        if event.get('event_action') == 'blocked' and event.get('log_type') == 'utm':
            application.put("blocked_events", True, 86400)
            return 0.75

    return 0.0

def context(event_data): 

    # Safely extract values with defaults
    device = event_data.get('source_device_name')
    source_ip = event_data.get('source_ip')
    destination_ip = event_data.get('destination_ip')
    destination_port = event_data.get('destination_port')
    policy_id = event_data.get('policy_id')
    protocol = event_data.get('network_protocol')
    action = event_data.get('event_action')
    details = event_data.get('event_details')
    log_type = event_data.get('log_type')
    log_subtype = event_data.get('log_subtype')

    message = (
        "The FortiGate device {device} detected '{action}' event for {log_type} actions with subtype {log_subtype} "
        "for source IP {source_ip}."
        "The most recent event shows a connection to {destination_ip}:{destination_port} "
        "because the firewall {details} under policy ID {policy_id} using the {protocol} protocol. "
        "Such consistent blocking of outbound connections from a single user or host may indicate automated connection retries, "
        "credential-stuffing activity, or a misconfigured application repeatedly attempting disallowed traffic."
    ).format(
        device=device,
        action=action,
        log_type=log_type,
        source_ip=source_ip,
        protocol=protocol,
        destination_ip=destination_ip,
        destination_port=destination_port,
        policy_id=policy_id,
        details=details,
        log_subtype=log_subtype,
    )
    return message

def criticality():
    return 'HIGH'

def tactic():
    return 'Command and Control (TA0011)'

def technique():
    return 'Application Layer Protocol (T1071)'

def artifacts():
    return stats.collect(['event_action', 'log_type', 'log_subtype', 'event_type', 'source_ip', 'destination_ip', 'destination_country', 'source_device_name', 'url', 'user_agent'])

def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}