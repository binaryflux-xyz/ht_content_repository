def window():
  return None
  
def groupby():
  return ['event_interface']


def algorithm(event):
    key = application.get("budget_power")

    if key is True:
        return 0.0

    if "Available POE budget" in event.get("event_details"):
      application.put("budget_power", True, 86400)
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