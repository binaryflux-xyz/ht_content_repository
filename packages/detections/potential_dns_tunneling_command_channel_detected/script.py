def window():
    return '10m'
def groupby():
    return ['destination_domain']
def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
def algorithm(event):
    evt_id = str(event.get("event_id"))
  
    if evt_id != "22":
        return 0.0
      
    domain = event.get("destination_domain")
    if not domain or domain in ["-", "UNKNOWN", None]:
        return 0.0
      
    if event.get('event_id') == 22 and stats.count('dns_tunneling_query_name_detection') > 50:
        stats.resetcount('dns_tunneling_query_name_detection')
        return 1
      
    return 0.0

  
def context(event_data):
    domain = event_data.get("destination_domain")
    src_ip = event_data.get("source_ip")
    host = event_data.get("host")
    count = stats.count('dns_tunneling_query_name_detection')

    return (
        "Domain '%s' received %s DNS queries within 10 minutes from host '%s' (source IP: %s). "
        "This may indicate DNS tunneling or command-and-control activity."
    ) % (domain, str(count), host, src_ip)

  
def criticality():
    return 'CRITICAL'
def tactic():
    return 'Command and Control (TA0011)'
def technique():
    return 'Application Layer Protocol (T1071/004)'
def artifacts():
    return stats.collect([  "host","source_ip","destination_domain","destination_ip","source_port",'event_id'])
def entity(event):
    return {'derived': False, 'value': event.get('destination_domain'), 'type': 'dns'}