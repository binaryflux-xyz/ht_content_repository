from datetime import datetime
import time

# this to return True/False based on which this message will qualify to be used for datamodel
def criteria(metainfo):
    return metainfo['provider'] == 'trendmicro' and metainfo['group'] == 'antivirus' \
        and metainfo['type'] == 'logs'

def timestamp(event):
    iso_str=event.get("timestamp")
    # Parse the ISO string (no microseconds or timezone here)
    dt = datetime.datetime.strptime(iso_str, "%Y-%m-%dT%H:%M:%S")
    # Convert to time tuple and get seconds since epoch
    seconds_since_epoch = time.mktime(dt.timetuple())
    # Convert to milliseconds
    millis = int(seconds_since_epoch * 1000)
    return millis 


def message(event):
    event_message = event.get("message")
    return event_message


def dictionary(event):
    endpoint_id = event.get("details").get("Endpoint ID")
    detection_type = event.get("details").get("Detection Type")
    action= event.get("details").get("Action Taken")
    file_path = event.get("details").get("File Path")   
    process_name = event.get("details").get("Process Name")
    malware_name = event.get("details").get("Malware Name")

    datamap= {
        "source_hostname": event.get("hostname"),
        "applicationname": event.get("application"),
        "event_name": event.get("event_name"),
        "details": event.get("details"),
    }
    if(endpoint_id):
        datamap['destination_security_id'] = endpoint_id
    if(detection_type): 
        datamap['event_type'] = detection_type
    if(action):
        datamap['event_action'] = action
    if(file_path):
        datamap['file_path'] = file_path
    if(process_name):
        datamap['process_name'] = process_name
    if(malware_name):
        datamap['malware_name'] = malware_name


    return datamap

