
def window():
    return None


def groupby():
    return None

def investigate():
    return "fortigate_session_analyser"
  
def automate():
    return True

def algorithm(event):

    if (
        event.get("event_category_id") is not None
        and event.get("user_name") is not None
        and event.get("user_name") not in ["UNKNOWN", "N/A"]
        and event.get("event_category_id") is not None
        and any(
            category in str(event.get("event_category_id"))
            for category in [
                "Malicious",
                "Phishing",
                "Potential Unwanted Software",
                "Scam",
                "Suspicious",
                "ilac",
                "Browser Exploits",
                "Potential Illegal Software",
                "PUPs",
                "Spyware",
                "Computer Hacking",
                "Botnet",
                "Spam",
                "malware",
                "Unclassified",
                "128",
                "154",
                "164",
                "166",
                "167",
                "172",
                "193",
                "194",
                "200",
                "205",
                "206",
                "207",
                "213",
                "214",
                "218",
                "219",
                "220",
                "Criminal Activity",
                "Hacking",
                "Spam URLs",
                "Phishing & Fraud",
                "ilac",
            ]
        )
    ):
        return 0.75
    else:
        return 0.0


def context(event_data):
    os_name = event_data.get("os_name")
    source_ip = event_data.get("source_ip")
    network_protocol = event_data.get("network_protocol")
    destination_country = event_data.get("destination_country")
    destination_ip = event_data.get("destination_ip")
    event_duration = event_data.get("event_duration")
    network_bytes_out = event_data.get("network_bytes_out")
    network_bytes_in = event_data.get("network_bytes_in")
    applicationname = event_data.get("applicationname")
    application_category = event_data.get("application_category")
    application_risk = event_data.get("application_risk")
    policy_type = event_data.get("policy_type")
    policy_id = event_data.get("policy_id")

    return (
        "A " + (os_name or "device") +
        " with IP " + (source_ip or "unknown") +
        " initiated an outbound connection over the " + (network_protocol or "unknown") +
        " protocol to a destination in " + (destination_country or "an unknown country") +
        " (" + (destination_ip or "unknown IP") + "). "
        "The connection lasted for " + (event_duration or "unknown") + " seconds, "
        "sending " + (network_bytes_out or "unknown") + " bytes and receiving " + (network_bytes_in or "unknown") + " bytes. "
        "The application involved was '" + (applicationname or "unknown") + "', "
        "categorized under '" + (application_category or "uncategorized") + "' "
        "with a risk level of '" + (application_risk or "unknown") + "'. "
        "The destination or activity was classified as malicious or high-risk according to policy "
        + (policy_type or "unknown") + " (" + (policy_id or "N/A") + ")."
    )


def criticality():
    return "HIGH"

def tactic():
    return "Command and Control(TA0011)"

def technique():
    return "Application Layer Protocol (T1071)"

def artifacts():
    try:
        return stats.collect(["event_category_id", "source_ip", "network_protocol", "applicationname","destination_country"])
    except Exception as e:
        raise e

def entity(event):
    return {"derived": False, "value": event.get("source_ip"), "type": "ipaddress"}