# Detection: High-Frequency Failed Logons from Single Source to Account
# Purpose: Detect multiple failed logon attempts from the same source IP targeting the same user account
#          within a short time window, indicating possible brute-force activity.
# Schema: Unified `source_` / `destination_` naming
# Event: 4625 (Failed Logon)
# MITRE: Credential Access (TA0006) / Brute Force (T1110)


def window():
    return '5m'  # rolling window of 10 minutes


def groupby():
    # Group by destination account and source IP
    return ['destination_account_name', 'source_ip']
def investigate():
    return "windows_server_session_analyser"

def automate():
    return False

# def algorithm(event):
#     event_id = event.get('event_id')
#     event_type = event.get('event_type', '').upper()
#     dest_user = event.get('destination_account_name', '-')
#     src_ip = event.get('source_ip', '-')

#     # Identify failed login events
#     if event_id in [4625, 4673] or 'FAILURE' in event_type:
        
#         # Trigger alert if failures exceed threshold (e.g. 5)
#         if stats.count("failed_logons_per_source_account") >= 5:
#             stats.resetcount("failed_logons_per_source_account")
#             return 0.5
#         return 0.0

#     return 0.0

def algorithm(event):

    evt_id = str(event.get("event_id") or "")
    if evt_id != "4625":  # Only failed logons
        return 0.0

    src_ip = event.get("source_ip")
    acct = event.get("destination_account_name")

    if not src_ip or src_ip in ["-", "UNKNOWN", "127.0.0.1", "::1"]:
        return 0.0
    if not acct or acct in ["-", "UNKNOWN", None]:
        return 0.0

    if  stats.count("failed_logons_per_source_account") >= 5:
        stats.resetcount("failed_logons_per_source_account")
        return 0.75  # fixed high-confidence score

    return 0.0


def context(event_data):
    src_ip = event_data.get("source_ip") or "-"
    acct = event_data.get("destination_account_name") or "-"
    domain = event_data.get("destination_account_domain") or "-"
    host = event_data.get("host") or "-"
    fail_count = event_data.get("fail_count", "N/A")

    return (
        "Detected %s failed logon attempts from source IP '%s' targeting account '%s\\%s' "
        "on host '%s' within 5 minutes. This indicates possible brute-force activity."
    ) % (fail_count, src_ip, domain, acct, host, TIME_WINDOW)


def criticality():
    return "HIGH"


def tactic():
    return "Credential Access (TA0006)"


def technique():
    return "Brute Force (T1110)"


def artifacts():
    return stats.collect([
        "event_id",
        "event_type",
       "host",
        "source_ip",
        "source_port",
        "destination_account_name",
        "destination_account_domain",
    ])


def entity(event):
    # The primary entity under attack is the destination account
    return {
        "derived": False,
        "value": event.get("destination_account_name"),
        "type": "accountname"
    }
