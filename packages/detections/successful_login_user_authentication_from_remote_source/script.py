def window(): 
  return None
  
def groupby(): 
  return ['user_name']

def algorithm(event):
    key = application.get("cisco_login_success")

    if key is True:
        return 0.0
    
    if event.get("event_facility") in ["SSH", "SEC_LOGIN"] and \
       ("Succeeded" in event.get("event_details") or \
        "Login Success" in event.get("event_details")):
            application.put("cisco_login_success", True, 86400)
            return 0.50
    return 0.0



def context(event_data):
  code = event_data.get("event_code")
  user = event_data.get("user_name")
  src_ip = event_data.get("source_ip")
  facility = event_data.get("event_facility")
  message = (
    "This event shows multiple {code} events for user '{user}' "
    "from source IP {src_ip} under facility {facility}."
  ).format(code=code, user=user, src_ip=src_ip, facility=facility)
  return message

def criticality(): 
  return "MEDIUM"
  
def tactic():
  return "Defense Evasion (TA0005)"

def technique(): 
  return "Impair Defenses (T1562)"
  
def artifacts():
    return stats.collect(['event_facility', 'event_code', 'user_name', 'source_ip'])

def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}