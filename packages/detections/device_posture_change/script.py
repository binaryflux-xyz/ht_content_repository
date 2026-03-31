def window():
    return "10m"

def groupby():
    return ["mac_address"]

def algorithm(event):
    posture = (event.get("posture_status") or "").lower()

    if posture in ["non-compliant","failed","unhealthy"]:
        return 0.75

    return 0.0

def context(event):
    return (
        "Device posture changed to non-compliant for MAC " +
        str(event.get("mac_address")) +
        " (possible security control bypass)"
    )

def criticality():
    return "HIGH"

def tactic():
    return "Defense Evasion (TA0005)"

def technique():
    return "Impair Defenses (T1562)"

def artifacts():
    return stats.collect(["mac_address","ip_address","posture_status","device_name"])

def entity(event):
    return {"derived": False, "value": event.get("mac_address"), "type": "mac"}