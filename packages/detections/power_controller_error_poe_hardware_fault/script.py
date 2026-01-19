def window():
  return '1d'
  
def groupby():
  return ["event_interface"]

def algorithm(event):
    key = application.get("power_fail")

    if key is True:
        return 0.0

    if event.get("event_facility") == "ILPOWER":
        details = event.get("event_details", "")
        if any(err in details for err in ["Tstart error detected", "overcurrent", "short circuit error"]):
            application.put("power_fail", True, 86400)
            return 0.75

    return 0.0

def context(event_data):
    details = event_data.get("event_details")  
    return details

def criticality():
  return "HIGH"

def tactic():
  return "Impact (TA0040)"
  
def technique():
  return "Service Stop (T1489)"

def artifacts():
    return stats.collect(['event_interface', 'event_facility', 'event_code'])

def entity(event):
    return {"derived": False, "value": event.get("event_interface"), "type": "interface"}