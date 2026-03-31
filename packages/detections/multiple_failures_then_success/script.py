
def window():
    return '10m'  # rolling window of 10 minutes






def groupby():
    # aggregate per host + user + source IP
    return ['host', 'source_account_name', 'source_ip']

def investigate():
    return "bruteforce_attack"

def automate():
    return False

def algorithm(event):

    user = event.get('source_account_name')
    host = event.get('host')
    src_ip = event.get('source_ip')
   
    is_failure = False
    if event.get('event_type') and 'FAILURE' in event.get('event_type').upper() :
        is_failure = True
    if event.get('event_id') in [4625, 4673]:
        is_failure = True

    # Count failures
    if is_failure:
        stats.count("failedloginfollowedbysuccess")
        return 0.0

    # Determine success events
    is_success = False
    if event.get('event_type') and 'SUCCESS' in event.get('event_type').upper():
        is_success = True
    if event.get('event_id') == 4624:
        is_success = True

    if is_success:
      prior_failures = stats.getcount("failedloginfollowedbysuccess")
      if prior_failures >= 5:
          return 0.75

    return 0.0

def context(event_data):
   
    return "User " + event_data.get('source_account_name')+ " from host "+ event_data.get('host')+ " having IP " + event_data.get('source_ip') + " attempted multiple failed logins followed by a success." 

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
                "event_type",
                "host",
                "source_account_name",
                "source_ip",
                "source_ip"
            ])
def entity(event):
    return {"derived": False, "value": event.get("source_account_name"), "type": "accountname"}
