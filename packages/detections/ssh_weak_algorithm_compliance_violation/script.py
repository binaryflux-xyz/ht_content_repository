def window(): 
  return "1d"
  
def groupby(): 
  return ["event_code"]

def algorithm(event):
    key = application.get("weak_key")

    if key is True:
        return 0.0

    details = event.get("event_details") or ""

    if event.get("event_facility") == "SSH" and "weaker Public-key Algorithm" in details:
        application.put("weak_key", True, 86400)
        return 0.50

    return 0.0

def context(event_data):
    details = event_data.get("event_details")
    return details

def criticality(): 
  return "MEDIUM"
  
def tactic():
  return "Defense Evasion (TA0005)"

def technique(): 
  return "Impair Defenses (T1562)"
  
def artifacts():
    return stats.collect(['event_facility', 'event_code'])

def entity(event):
    return {"derived": False, "value": event.get("event_code"), "type": "event-type"}