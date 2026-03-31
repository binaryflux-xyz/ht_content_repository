def window():
    return "30m"


def groupby():
    return ["source_ip"]


def algorithm(event):

    dst_ip = event.get("destination_ip")
    country = event.get("destination_country")
    bytes_out = event.get("network_bytes_out")

    if not dst_ip or not country or not bytes_out:
        return 0.0

    # Ignore internal traffic
    if (
        dst_ip.startswith("10.") or
        dst_ip.startswith("192.168.") or
        dst_ip.startswith("172.")
    ):
        return 0.0

    bytes_out = int(bytes_out)

    # Ignore small transfers
    if bytes_out < 10000000:  # 10MB
        return 0.0

    # Check rarity of country
    rare_country = stats.rarity("destination_country")

    if rare_country == 1.0:
        return 0.75

    return 0.0


def context(event_data):

    return (
        "Large outbound data transfer detected from source IP "
        + str(event_data.get("source_ip")) +
        " to destination IP "
        + str(event_data.get("destination_ip")) +
        " located in a rare country ("
        + str(event_data.get("destination_country")) +
        "). The data transfer volume was "
        + str(event_data.get("network_bytes_out")) +
        " bytes, which may indicate potential data exfiltration."
    )


def criticality():
    return "HIGH"


def tactic():
    return "Exfiltration (TA0010)"


def technique():
    return "Exfiltration Over Network (T1041)"


def artifacts():
    return stats.collect([
        "source_ip",
        "destination_ip",
        "destination_country",
        "network_bytes_out",
        "destination_port",
        "network_protocol"
    ])


def entity(event):
    return {
        "derived": False,
        "value": event.get("source_ip"),
        "type": "ipaddress"
    }