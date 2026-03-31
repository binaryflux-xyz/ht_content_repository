SYN_THRESHOLD = 50  # More than 50 half-open SYNs per IP

def window():
    return '10s'

def groupby():
    return ['destination_ip']

def algorithm(event):
    
    method = event.get('http.request.method')
    count = stats.getcount("tcp_syn_flood")
    # print(method.lower() + " " + event['source_ip']+" "+ str(count))
    if method and method.lower() == 'get' and stats.count("tcp_syn_flood") > SYN_THRESHOLD:
      print("-----------------------------------------")
      return 1.0

def investigate():
    return 'block_ip_address'

def automate():
    return False
  
def context(event_data):

    destination_ip = event_data.get("destination_ip")
    return "SYN Flood Detected: Host "+destination_ip+" received over 50 half-open SYN packets within 10 seconds."
    
def criticality():
    return "HIGH"


def tactic():
    return "Impact (TA0040)"


def technique():
    return "Network Denial of Service (T1498)"


def entity(event):
    return {"derived": False, "value": event.get("destination_ip"), "type": "ipaddress"}


def artifacts():
    try:
        return stats.collect(
            [
                "source_ip",
                "destination_ip",
                "http.request"
            ]
        )
    except Exception as e:
        raise e
