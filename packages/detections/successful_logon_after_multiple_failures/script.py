
#eventid=4625,4673,4624

def window():
    return '10m'  # rolling window of 10 minutes



def groupby():
    # aggregate per host + user + source IP
    return ['destination_account_name']

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False

def algorithm(event):

    user = event.get('destination_account_name')
    evt_id = event.get("event_id")
    logon_type = int(event.get("logon_type", 0))

    if not user or user in ["-", "UNKNOWN", None]:
        return 0.0
      
    if logon_type == 5:
        return 0.0
   
    is_failure = False
    if evt_id in [4625, 4673]:
        is_failure = True

    # Count failures
    if is_failure:
        stats.count("failedloginfollowedbysuccess")
        return 0.0

    # Determine success events
    is_success = False
    if evt_id == 4624:
        is_success = True

    if is_success:
      prior_failures = stats.getcount("failedloginfollowedbysuccess")
      if prior_failures >= 5:
          return 0.75

    return 0.0

def context(event_data):
    acct = event_data.get("destination_account_name")
    domain = event_data.get("destination_account_domain") 
    src_ip = event_data.get("source_ip")
    host = event_data.get("host")
    prior_failures = stats.getcount("failedloginfollowedbysuccess")

    return (
        "Account '%s\\%s' successfully logged on from '%s' after %s failed attempts within 10 minutes "
        "on host '%s'. This may indicate a guessed password or brute-force attack."
    ) % (domain, acct, src_ip, prior_failures, host)

def criticality():
    return "HIGH"

def tactic():
    return "Credential Access (TA0006)"

def technique():
    return "Brute Force (T1110)"

def artifacts():
        return stats.collect(
            [
                "event_id",
                "host",
        "destination_account_name",
        "destination_account_domain",
                "source_ip",
              "logon_type",
            ])
def entity(event):
    return {"derived": False, "value": event.get("destination_account_name"), "type": "accountname"}
