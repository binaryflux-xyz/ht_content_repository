def window():
    return '10m'

def groupby():
    return ['source_ip']

def investigate():
    return "fortigate_session_analyser"
  
def automate():
    return True

def algorithm(event):

    destination_ip = event.get("destination_ip")
    destination_ports = ["23", "22", "3389"]
    application_protocols = ["ICMP", "TELNET", "ssh", "RDP"]
    account_name = event.get("user_name")

    sentbytes = (
        int(event.get("network_bytes_out"))
        if event.get("network_bytes_out") is not None
        else 0
    )
    receivedbytes = (
        int(event.get("network_bytes_in"))
        if event.get("network_bytes_in") is not None
        else 0
    )

    bytesTransferred = sentbytes + receivedbytes
    threshold = 1000000000  # to be taken from variable
    rangeooutsie=cidr.inRange(destination_ip,"10.0.0.0/8")


    condition1 = event.get("destination_port") == "53" or (
        event.get("network_protocol") is not None
        and ("HTTP" in event.get("network_protocol") or "HTTPS" in event.get("network_protocol"))
    )


    condition2 = (
        event.get("destination_port") in destination_ports
        or event.get("network_protocol") in application_protocols
    ) and (
        account_name is not None
        and account_name not in ["-", "UNKNOWN", ""]
        and "$" not in account_name
    )

    final_condition = condition1 or condition2

    if final_condition:
        stats.count("abnormal")
        count = stats.getcount("abnormal")

        # trigger ONLY when count == 25
        if count == 25 and rangeooutsie and bytesTransferred >= threshold:
            return 0.75
        # otherwise just count, no detection
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
    context = "A "

    if os_name:
        context += os_name + " device "
    if source_ip:
        context += "(IP: " + source_ip + ") "
    context += "initiated a secure connection over "

    if network_protocol:
        context += network_protocol + " protocol to a destination in "
    if destination_country:
        context += destination_country + " "
    if destination_ip:
        context += "(IP: " + destination_ip + "), which is within the range of the organization's CIDR. "

    if event_duration:
        context += "The connection lasted for " + str(event_duration) + " seconds, "
    if network_bytes_out:
        context += "with " + str(network_bytes_out) + " bytes sent from the network and "
    if network_bytes_in:
        context += str(network_bytes_in) + " bytes received on the network, which exceeds the threshold of 1 GB. "

    if applicationname:
        context += "The identified application was " + applicationname + ", "
    if application_category:
        context += "categorized under " + application_category + ", "
    if application_risk:
        context += "with a risk level of " + application_risk + ". "

    context += "This activity triggered a detection log, indicating an abnormal amount of data transmitted via HTTP/HTTPS ports, in accordance with "

    if policy_id:
        context += " policy ID " + policy_id + "."

    return context
    
def criticality():
    count = stats.getcount("abnormal")
    if count == 25:
        return "HIGH"


def tactic():
    return "Exfiltration (TA0010)"


def technique():
    return "Exfiltration Over Alternative Protocol (T1048)"


def entity(event):
    return {"derived": False, "value": event.get("source_ip"), "type": "ipaddress"}

def artifacts():
    try:
        return stats.collect(
            [
                "source_ip",
                "network_protocol",
                "network_bytes_out",
                "network_bytes_in",
                "destination_ip",
                "destination_country"
            ]
        )
    except Exception as e:
        raise e
