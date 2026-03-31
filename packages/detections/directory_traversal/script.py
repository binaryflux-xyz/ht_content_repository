def window():
    return "5m"

def groupby():
    return ["source_ip"]

def algorithm(event):
    url = (event.get("url") or "").lower()

    if "../" in url or "..\\" in url:
        return 0.75
    return 0.0

def context(event):
    return "Directory traversal attempt from " + str(event.get("source_ip")) + " URL: " + str(event.get("url"))

def criticality():
    return "HIGH"

def tactic():
    return "Initial Access (TA0001)"

def technique():
    return "Exploitation for Client Execution (T1203)"

def artifacts():
    return stats.collect(["source_ip","url"])

def entity(event):
    return {"derived": False, "value": event.get("source_ip"), "type": "ipaddress"}