def window():
    return '15m'

def groupby():
    # Group by source_ip (since instance_id is inside details)
    return ['source_ip', 'destination_ip']

def investigate():
    return 'vpc_session_analyser'

def automate():
    return False

def algorithm(event):
    direction = event.get('network_direction')
    src_ip = event.get('source_ip', '') or ''
    dst_ip = event.get('destination_ip', '') or ''
    dst_port = event.get('destination_port')
    try:
        port = int(dst_port) if dst_port is not None else 0
    except Exception:
        port = 0

    key = 'vpc_rare_port_{}_{}_{}'.format(src_ip, dst_ip, port)
    key_exists = application.get(key)
    if key_exists is True:
        return 0.0
    common_ports = [80, 443, 53, 123, 11443]

    # Rough private IP check
    is_private_dest = dst_ip.startswith(('10.', '172.', '192.168.'))

    if direction == 'Outbound' and not is_private_dest:
        if port not in common_ports and port > 0:
            if stats.count(key) > 5:
              application.put(key, True, 86400)
              return 0.75
    return 0.0

def context(event):
    stats.resetcount('vpc_rare_port_{}_{}_{}'.format(event.get('source_ip', ''), event.get('destination_ip', ''), event.get('destination_port')))
    return (
        "Host {src} is communicating over uncommon port {port} to external destination {dst}."
    ).format(
        src=event.get('source_ip'),
        port=event.get('destination_port'),
        dst=event.get('destination_ip')
    )

def criticality():
    return 'MEDIUM'

def tactic():
    return 'Command and Control'

def technique():
    return 'Non-Standard Port (T1571)'

def artifacts():
    return stats.collect(['source_ip', 'destination_ip', 'destination_port', 'network_protocol'])

def entity(event):
    """
    Identifies the primary entity related to this detection.
    Can be directly from event attribute or derived.
    """
    return {
        "derived": False,
        "value": event.get("source_ip", "unknown"),
        "type": "ipaddress"
    }