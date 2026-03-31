from datetime import datetime


def window():
    return "15m"


def groupby():
    return ["source_ip"]


def algorithm(event):

    timestamp = event.get("timestamp")
    bytes_out = event.get("network_bytes_out")

    if not timestamp or not bytes_out:
        return 0.0

    try:
        # eventtime already converted to ms in dictionary
        dt = datetime.utcfromtimestamp(int(timestamp) / 1000)
        hour = dt.hour
    except:
        return 0.0

    bytes_out = int(bytes_out)

    # Ignore small transfers
    if bytes_out < 5000000:  # 5MB
        return 0.0

    # Define unusual hours (example: 10 PM - 6 AM)
    if hour >= 22 or hour <= 6:
        return 0.75

    return 0.0


def context(event_data):

    return (
        "Unusual data transfer detected from source IP "
        + str(event_data.get("source_ip")) +
        " to destination IP "
        + str(event_data.get("destination_ip")) +
        " during off-hours. A total of "
        + str(event_data.get("network_bytes_out")) +
        " bytes were transferred outside normal business hours."
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