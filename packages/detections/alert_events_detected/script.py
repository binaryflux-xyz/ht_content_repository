def window():
    return None


def groupby():
    return ['source_remote_ip']

def investigate():
    return "fortigate_ip_session_analyser"
  
def automate():
    return True

def algorithm(event):
    event_level = event.get("event_level")
    action = event.get("event_action")
    key = application.get("alert_level")

    if key is True:
        return 0.0
      
    if event_level == 1 and action == "ssl-login-fail":
        application.put("alert_level", True, 86400)
        return 0.75
    return 0.0

def context(event_data):
  event = event_data.get("event")
  user = event_data.get("user_name")
  country = event_data.get("source_country")
  type = event_data.get("log_subtype")
  device = event_data.get("source_device_name")
  ip = event_data.get("source_remote_ip")
  tunnel = event_data.get("tunnel_type")
  context = "A Fortigate firewall logged an alert-level event that may indicate a security issue "
  if event:
    context += "due to  " + event + " "
  if user:
    context += "for user " + user + " "
  if country:
    context += "from source country " + country + " "
  if ip:
    context += "with remote ip " + ip + " "
  if tunnel:
    context += "and tunnel type " + tunnel + " "
  if type:
    context += "while using " + type + " "
  if device:
    context += "for device " + device + " "
  context += "Review the event to verify system and take corrective action if needed."
  return context

def criticality():
    return "HIGH"

def tactic():
    return "Command and Control (TA0011)"

def technique():
    return "Application Layer Protocol (T1071)"

def artifacts():
    return stats.collect(['user_name', 'log_subtype', 'event_action', 'source_country', 'source_remote_ip', 'tunnel_type'])

def entity(event):
    return {"derived": False, "value": event.get("source_remote_ip"), "type": "remoteip"}


