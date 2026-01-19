# sample name -> realtime-detections/authentication/brute_force_login.py
def window():
    return '10m'
  
def groupby():
    return ['destination_account_name']

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
  
def algorithm(event):
    acct = (event.get('destination_account_name') or "").strip()
    source_ip = event.get('source_ip')
    if acct and acct.endswith('$'):
        return 0.0
    if not source_ip or source_ip in ['::1', 'UNKNOWN', '127.0.0.1', '-']:
      return 0.0
    
    if event.get('event_id') == 4625:
        if stats.count('high_frequency_failed_logons_for_account_name') >= 5:
            stats.resetcount('high_frequency_failed_logons_for_account_name')
            return 0.75
    return 0.0


def context(event_data):
    account = event_data.get('destination_account_name')
    host = event_data.get('host')
    process = event_data.get('source_process_name')
    sourceipsdict = stats.collect(['source_ip'])
    unique_ips = list(set(sourceipsdict.get("source_ip", [])))

    if not account or account == "-":
        account = "an unknown account"

    if len(unique_ips) == 1:
        single_ip = event_data.get("source_ip")
        if not single_ip or single_ip == "-":
            if unique_ips:
                single_ip = unique_ips[0]
            else:
                single_ip = None
        if single_ip :
          return (
            "Multiple failed logins were detected for account "
            + str(account)
            + " on host "
            + str(host)
            + " originating from a single IP: "
            + str(single_ip)
            + ". "
            "This may indicate repeated access attempts or automated activity from that source."
        )
    elif process:
      return (
        "Repeated network logon failures by process "
        + str(process)
        + " on host "
        + str(host)
        + " for locked account: "
        + str(account)
        + ". "
        "It’s not an external attack, but a local service or scheduled task using stale credentials."
      )
    else:
        return (
            "Multiple logins were detected for account "
            + str(account)
            + " on host "
            + str(host)
            + " originating from multiple IPs. "
            "This may indicate account sharing or a distributed brute-force attempt."
        )

  
def criticality():
    return 'HIGH'
  
def tactic():
    return 'Credential Access (TA0006)'
  
def technique():
    return 'Brute Force (T1110)'
  
def artifacts():
    return stats.collect(['source_ip','event_type','host'])
  
def entity(event):
    return {'derived': False, 'value': event.get('destination_account_name'), 'type': 'accountname'}
