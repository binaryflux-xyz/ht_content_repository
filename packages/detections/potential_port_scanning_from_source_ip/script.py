def window():
    return '2m'  # rolling 2-minute window


def groupby():
    # Track blocked connections per host and source IP
    return [ 'source_ip']

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False

def _is_private_ip(ip):
    """Simple private / link-local IP detection. Returns True for private/local addresses."""
    if not ip or ip in ["-", "UNKNOWN", None]:
        return False
    ip = str(ip).strip()
    try:
        # IPv4 checks (fast, simple)
        parts = ip.split('.')
        if len(parts) == 4:
            a,b,c,d = [int(x) for x in parts]
            # 10.0.0.0/8
            if a == 10:
                return True
            # 172.16.0.0/12
            if a == 172 and 16 <= b <= 31:
                return True
            # 192.168.0.0/16
            if a == 192 and b == 168:
                return True
            # Link-local 169.254.0.0/16
            if a == 169 and b == 254:
                return True
        # IPv6 quick checks
        if ip.startswith('fe80') or ip.startswith('fc') or ip.startswith('fd') or ip == '::1':
            return True
    except Exception:
        pass
    return False


def algorithm(event):
    event_id = event.get('event_id')
    src_ip = event.get('source_ip')
  
    if event_id not in [5152, 5157]:
          return 0.0
      
    if not src_ip or src_ip in ["-", "UNKNOWN", None]:
        return 0.0

    if _is_private_ip(src_ip):
        return 0.0

    blocked_count = stats.count("blocked_connections_per_source")  # counts all events in group/window

    if blocked_count > 50:
      return 0.5
    return 0.0


def context(event_data):
    src_ip = event_data.get("source_ip")
    dst_host = event_data.get("host")
    blocked_count = stats.count("blocked_connections_per_source")
    return (
        "External IP %s generated over %s blocked firewall connection attempts "
        "to host '%s' within 2 minutes, indicating possible port scanning activity."
    ) % (src_ip, blocked_count, dst_host)


def criticality():
    return 'MEDIUM'


def tactic():
    return 'Reconnaissance (TA0043)'


def technique():
    return 'Network Scanning (T1595)'


def artifacts():
    return stats.collect([
        'host',
        'source_ip',
        'destination_port',
      "source_port",
        'event_id'
    ])



def entity(event):
    return {
        'derived': False,
        'value': event.get('source_ip'),
        'type': 'ipaddress'
    }
