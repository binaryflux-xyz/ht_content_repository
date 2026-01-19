def window():
    return None
    
def groupby():
    return None

def investigate():
    return "fortigate_session_analyser"
  
def automate():
    return True
    
def algorithm(event):
    if event.get('network_request_method')=='domain' and event.get('event_action')=='blocked' and event.get('event_category_desc') is not None and 'Malicious' in event.get('event_category_desc'):
        return 0.75
    return 0.0

def context(event_data):
    source_device_name=event_data.get('source_device_name')
    event_type=event_data.get('event_type')
    source_device_interface=event_data.get('source_device_interface')
    user_name=event_data.get('user_name')
    user_group=event_data.get('user_group')
    destination_ip=event_data.get('destination_ip')
    destination_device_interface=event_data.get('destination_device_interface')
    level=event_data.get('level')
    event_category_desc=event_data.get('event_category_desc')
    network_request_method=event_data.get('network_request_method')
    details=event_data.get('details')
    deatils_url=event_data.get('url')
    source_ip=event_data.get('source_ip')

    return (
        "This log entry, originating from the security system "+  
       ( source_device_name if source_device_name else 'None')+
        ", indicates a web filtering event of type "+ 
       ( event_type if event_type else 'None') +
        " with a "+ 
        (level if level else 'None')+
        " level. It records an attempt to access a URL identified by the key "+ 
       ( deatils_url if deatils_url else 'None')+
        ",which has been categorized as "+ 
       ( event_category_desc if event_category_desc else 'None')+
        ". The policy enforcement, triggered by the conditions outlined in the detection rule, has resulted in blocking the access attempt. Notably, the attempt was made from IP address "+
        (source_ip if source_ip else 'None')+
        ",originating from interface "+ 
       ( source_device_interface if source_device_interface else 'None')+
        " and belonging to user "+ 
       ( user_name if user_name else 'None')+
        " in group "+ 
        (user_group if user_group else 'None')+
        ". The destination IP address "+ 
       ( destination_ip if destination_ip else 'None')+
        " corresponds to interface "+
       ( destination_device_interface if destination_device_interface else 'None')+
        ". The detection method employed is "+
        (network_request_method if network_request_method else 'None')+
        ".This event underscores proactive measures taken by the system to mitigate potential security risks by enforcing policies against accessing known malicious domains."
        )
 
def criticality():
    return 'HIGH'
    
def tactic():
    return 'Command and Control (TA0011)'
    
def technique():
    return 'Application Layer Protocol (T1071)'

def artifacts():
    try:
        return stats.collect(['event_category_desc','event_action','source_device_name','source_ip','network_request_method','user_name'])
    except Exception as e:
        raise e


def entity(event):
    return {'derived': False,
            'value': event.get('source_ip'),
            'type': 'ipaddress'}