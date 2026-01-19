# Detection: Lateral Movement via SMB or RDP
# Purpose: Detect when the same account authenticates to multiple hosts using network or RDP logons
# Events: 4624 (successful logon) with LogonType 3 (network/SMB) or 10 (remote/ RDP)
# Condition: same account logs on to >3 distinct hosts within 15 minutes
# MITRE: Remote Services (T1021) / Lateral Movement (TA0008)

def window():
    return '5m'

def groupby():
    # aggregate per account to count distinct destination hosts
    return ['destination_account_name']

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False




def algorithm(event):
    # consider only successful logons (4624)
    evt_id = event.get('event_id')
    source_ip = event.get('source_ip')
    if evt_id != 4624:
        return 0.0
      
    if not source_ip or source_ip in ['::1', 'UNKNOWN','127.0.0.1','-']:
          return 0.0

    # ✅ Filter out machine accounts (like PROINDKOLDC15$)
    acct = (event.get('destination_account_name') or "").strip()
    if acct.endswith('$'):
        return 0.0  # skip machine/service accounts

    # logon type may be in different fields; normalize
    logon_type = int(event.get('logon_type'))

    # only network (3) or remote/interactive over network (10)
    if logon_type not in [3, 10]:
        return 0.0

    # per-account per-dest seen marker (so we count each destination host only once)
    host_dict = stats.collect(['host'])
    unique_host=len(host_dict.get("host"))
    if unique_host == 3:
      return 0.75

    return 0.0



def context(event_data):
    acct = event_data.get("destination_account_name")
    domain = event_data.get("destination_account_domain") or "-"
    host = event_data.get("host")
    src_ip = event_data.get("source_ip")
    lt = event_data.get("logon_type")
    host_dict = stats.collect(['host'])
    unique_host=len(host_dict.get("host"))

    # 🧩 Determine the logon method description dynamically
    if lt == "3":
        logon_desc = "a network logon (SMB, file share, or remote service access)"
    elif lt == "10":
        logon_desc = "a remote desktop (RDP) logon"
    else:
        logon_desc = "an unspecified logon type"

    return (
       "Account '%s\\%s' has authenticated to %s distinct hosts within the last 15 minutes "
        "using %s from source IP '%s'. Such behavior may indicate credential misuse or lateral movement activity."
      
    ) % (domain, acct, str(unique_host),logon_desc, src_ip)


def criticality():
    return "HIGH"

def tactic():
    return "Lateral Movement (TA0008)"

def technique():
    return "Remote Services (T1021/002)"

def artifacts():
    return stats.collect([
        "logon_type",
        "host",
        "destination_account_name",
        "source_ip",
  "source_port"
    ])



def entity(event):
    account = event.get('destination_account_name')
    return {"derived": False, "value": account, "type": "accountname"}
