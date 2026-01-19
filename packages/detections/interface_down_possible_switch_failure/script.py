def window(): 
  return None
  
def groupby(): 
  return ["event_interface"]

def algorithm(event):
    key = application.get("interface_down")

    # If weak_key is already set, always return 0.0
    if key is True:
        return 0.0

    if event.get("event_facility") in ["LINK", "LINEPROTO"] and "changed state to down" in event.get("event_details"):
        application.put("interface_down", True, 86400)
        return 1.0

    return 0.0

def context(event_data):
    msg = event_data.get("message")
    return msg

def criticality(): 
  return "CRITICAL"
  
def tactic():
  return "Impact (TA0040)"
  
def technique(): 
  return "Network Denial of Service (T1498)"
  
def artifacts():
    return stats.collect(['event_interface', 'event_facility', 'event_code'])

def entity(event):
    return {"derived": False, "value": event.get("event_interface"), "type": "interface"}
