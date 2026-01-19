

# Administrative and sensitive shares
SENSITIVE_SHARES = {"C$", "ADMIN$", "IPC$", "SYSVOL", "NETLOGON"}


def get_hostname_from_account(account):
    if account and account.endswith("$"):
        return account[:-1].lower()
    return None

def window():
    return None

def groupby():
    return None

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False

def _is_unmanaged_ip(ip):
    # Handle invalid or placeholder IPs
    if ip in [None, "-", "UNKNOWN", "0.0.0.0", "::1"]:
        return False

    # Query allowed or known hosts
    allowed_ip = tpi.query("AllowedIP", "ip = ?", [ip])

    # If no records found, it's unmanaged
    if not allowed_ip or not allowed_ip.get('rows'):
        return True

    # Extract allowed/known IPs
    allowed_ips = [row[0] for row in allowed_ip.get('rows', [])]
    print(allowed_ips)

    # If IP is not in known list, mark as unmanaged
    return ip not in allowed_ips

def allowed_host(account):
  if account and account.endswith("$"):
    acct_host = get_hostname_from_account(account)
    config_host = tpi.query("ConfigDetails", "Hostname = ?", [acct_host])
    if not config_host or not config_host.get('rows'):
      return True
    config_hosts = [row[0] for row in config_host.get('rows', [])]
    if acct_host and acct_host not in config_hosts:
        return True
  
  


def algorithm(event):
    evt_id = str(event.get("event_id"))
    share_name = event.get('share_name')
    source_account_name=event.get('source_account_name')
    if evt_id != "5140":  # File Share Access (SMB session)
        return 0.0

    src_ip = event.get("source_ip")

    if not src_ip or src_ip in ["127.0.0.1", "::1", "-", "UNKNOWN"]:
        return 0.0

    # Check inventory
    if _is_unmanaged_ip(src_ip) and allowed_host(source_account_name) and share_name in SENSITIVE_SHARES:
        return 0.75  # High confidence: SMB from unmanaged system

    return 0.0

def context(event):
    source_host = event.get("source_device_name") or "-"
    source_ip = event.get("source_ip") or "-"
    share_name = event.get("share_name") or "-"
    target_host = event.get("host") or "-"
    account = event.get("source_account_name") or "-"

    return (
        "Detected an SMB share access attempt from %s (%s) to '%s' on %s using account '%s'. "
        "The share is administrative or sensitive, and the connection originated from an untrusted or unusual source."
    ) % (source_host, source_ip, share_name, target_host, account)


    return message



def criticality():
    return "HIGH"

def tactic():
    return "Lateral Movement (TA0008)"

def technique():
    return "Remote Services (T1021/002)"

def artifacts():
    return stats.collect([
        "source_ip",
      "source_port",
       "share_name",
      "share_path",
     "event_id",
        "host",
      "source_account_name",
      "source_device_name"

    ])


def entity(event):
    src_ip =  event.get('source_ip')
    return {"derived": False, "value": src_ip, "type": "ipaddress"}
