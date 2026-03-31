def window():
    return "10m"


def groupby():
    return ["source_ip"]


def algorithm(event):

    protocol = (event.get("network_protocol") or "").lower()
    port = str(event.get("destination_port") or "")
    bytes_out = event.get("network_bytes_out")

    if not protocol or not port:
        return 0.0

    # Known protocol-port mapping
    standard_ports = {
        "http": ["80"],
        "https": ["443"],
        "dns": ["53"],
        "ssh": ["22"],
        "ftp": ["21"],
        "rdp": ["3389"]
    }

    # Check mismatch
    if protocol in standard_ports:
        if port not in standard_ports[protocol]:
            return 0.75

    # Suspicious protocols with high volume
    if protocol in ["dns", "icmp"]:
        if bytes_out and int(bytes_out) > 5000000:  # 5MB
            return 0.75

    return 0.0


def context(event_data):

    return (
        "Suspicious protocol usage detected from source IP "
        + str(event_data.get("source_ip")) +
        " communicating over protocol "
        + str(event_data.get("network_protocol")) +
        " on port "
        + str(event_data.get("destination_port")) +
        ". This behavior may indicate protocol tunneling or attempts to bypass security controls."
    )


def criticality():
    return "HIGH"


def tactic():
    return "Defense Evasion (TA0005)"


def technique():
    return "Protocol Tunneling (T1572)"


def artifacts():
    return stats.collect([
        "source_ip",
        "destination_ip",
        "destination_port",
        "network_protocol",
        "network_bytes_out"
    ])


def entity(event):
    return {
        "derived": False,
        "value": event.get("source_ip"),
        "type": "ipaddress"
    }