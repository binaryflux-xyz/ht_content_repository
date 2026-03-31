def window():
    return "15m"

def groupby():
    return ["mac_address"]

def algorithm(event):
    action = (event.get("event_action") or "").lower()
    evt = (event.get("event_type") or "").lower()

    if evt == "authentication" and action == "success":
        if stats.count("reauth") > 10:
            return 0.75

    return 0.0

def context(event):
    return (
        "Excessive device re-authentication detected for MAC " +
        str(event.get("mac_address"))
    )

def criticality():
    return "HIGH"

def tactic():
    return "Persistence (TA0003)"

def technique():
    return "Account Manipulation (T1098)"

def artifacts():
    return stats.collect(["mac_address","ip_address","auth_method"])

def entity(event):
    return {"derived": False, "value": event.get("mac_address"), "type": "mac"}