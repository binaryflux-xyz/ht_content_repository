def window():
    return '10m'
def groupby():
    return ['source_ip']
def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
  
def algorithm(event):
    if event.get('event_id') == 4624 and event.get('logon_type') == 10:
        if stats.count('source_ip') > 5:
            return 0.75
    return 0.0

  
def context(event_data):
    src_ip = event_data.get('source_ip', '-')
    dest_user = event_data.get('destination_account_name', '-')
    domain = event_data.get('destination_account_domain', '-')
    host = event_data.get('host', '-')
    process = event_data.get('logon_processname', '-')
    src_port = event_data.get('source_port', '-')

    return (
        "Multiple successful RDP (Logon Type 10) logons were detected within a 10-minute window. "
        "Source IP " + src_ip + " initiated more than five successful logons "
        "to host " + host + " targeting account " + dest_user + " "
        "under domain " + domain + " using process " + process + " "
        "on source port " + src_port + ". "
        "This behavior may indicate lateral movement or unauthorized remote access."
    )

def criticality():
    return 'HIGH'
def tactic():
    return 'Lateral Movement (TA0008)'
def technique():
    return 'Remote Services (T1021/001)'
  
def artifacts():
    return stats.collect([
        'source_ip',
        'destination_account_name',
        'logon_processname',
        'destination_account_domain',
        'host',
        'source_port'
    ])
def entity(event):
    return {'derived': False, 'value': event.get('source_ip'), 'type': 'ipaddress'}