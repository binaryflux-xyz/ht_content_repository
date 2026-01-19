# https://sc1.checkpoint.com/documents/R80.30/WebAdminGuides/EN/CP_R80.30_CLI_ReferenceGuide/html_frameset.htm?topic=documents/R80.30/WebAdminGuides/EN/CP_R80.30_CLI_ReferenceGuide/204659

from datetime import datetime
import time
import re


# this to return True/False based on which this message will qualify to be used for datamodel
def criteria(metainfo):
    return metainfo['provider'] == 'Check Point' and metainfo['group'] == 'Networking Devices' \
        and metainfo['type'] == 'Firewall'

def timestamp(event):
    obtainedevent=parse_log_line(event.get("message"))
    datestring = obtainedevent["timestamp"]
    # Remove timezone part (everything after '+')
    cleaned_date = datestring.split('+')[0]

    # Parse cleaned datetime
    dt = datetime.strptime(cleaned_date, "%Y-%m-%dT%H:%M:%S")

    # Convert to milliseconds since epoch
    epoch_time = time.mktime(dt.timetuple())
    milliseconds = int(epoch_time * 1000)
    return milliseconds


def message(event):
    if ( event.get("description")):
      return event.get("description")
    else:
      return "Message"


def parse_log_line(log_line):
    parts = log_line.split(' [Fields@', 1)
    prefix = parts[0].split()

    log_dict = {
        'log_index': int(prefix[0]),
        'timestamp': prefix[1],
        'source_ip': prefix[2],
        'device': prefix[3],
        'log_type': prefix[5],
        'fields': {}
    }

    fields_str = parts[1].rsplit(']', 1)[0]  # Trim trailing ']'
    key_values = re.findall(r'(\w+)="(.*?)"', fields_str)

    for key, value in key_values:
        log_dict['fields'][key] = value

    return log_dict

def dictionary(data):
    obtainedevent=parse_log_line(data.get("message"))
    event=obtainedevent.get("fields")
    modifdict={        
        "source_zone" : event.get("inzone"),
        "destination_zone" : event.get("outzone"),
        "source_device_name": event.get("device_name"),
        "source_ip": event.get("src"),
        "destination_ip": event.get("dst"),
        "source_port":event.get("sport_svc"),
        "destination_port":event.get("svc"),
        "network_application":event.get("service_id"),
        "event_action":event.get("action"),
        "event_interface":event.get("InterfaceName"),
        "product_name": event.get("ProductName"),
        "product_family":event.get("ProductFamily"),
        "rule":event.get("rule_name"),
        "source_device_name":event.get("Origin"),
        "source_device_id":event.get("OriginSicName"),
        "alert_name":event.get("layer_name"),
        "destination_domain":event.get("dst_domain_name"),
         "details": {
            "proto": event.get("proto"),
        },
    }
    return modifdict