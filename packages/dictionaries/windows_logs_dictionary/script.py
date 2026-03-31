import time
from datetime import datetime
import re


# this to return True/False based on which this message will qualify to be used for datamodel
def criteria(metainfo):
    return metainfo['provider'] == 'Microsoft' and metainfo['group'] == 'Windows Events' \
        and metainfo['type'] == 'Audit'


def timestamp(event):
    datestring = event["EventTime"]
    dt = datetime.strptime(datestring, "%Y-%m-%d %H:%M:%S")  # Parse the string to datetime
    epoch_time = time.mktime(dt.timetuple())  # Convert to seconds since epoch
    milliseconds = int(epoch_time * 1000)  # Convert to milliseconds
    return milliseconds

def modifydata(json_data):
    if "PrivilegeList" in json_data:
        privileges = re.split(r"\s+", json_data["PrivilegeList"].strip())  # Splitting on any whitespace
        json_data["PrivilegeList"] = [priv for priv in privileges if priv]  # Remove empty elements
    return json_data
  
# this to return user readable text as message extracted from event
def message(event):
    parts = []

    # Hostname and Event ID
    if event.get("Hostname"):
        parts.append("host {}".format(event["Hostname"]))
    if event.get("EventID"):
        parts.append("event ID {}".format(event["EventID"]))

    # Source info
    if event.get("SubjectUserName"):
        parts.append("initiated by account name {}".format(event["SubjectUserName"]))
    if event.get("IpAddress"):
        parts.append("from IP {}".format(event["IpAddress"]))
    if event.get("ProcessName"):
        parts.append("running process {}".format(event["ProcessName"]))

    # Severity
    if event.get("Severity"):
        parts.append("with severity {}".format(event["Severity"]))

    # Destination info
    dest_info = []
    if event.get("TargetUserName"):
        dest_info.append("user {}".format(event["TargetUserName"]))
    if event.get("DestAddress"):
        dest_info.append("at destination IP {}".format(event["DestAddress"]))
    if event.get("DestPort"):
        dest_info.append("on port {}".format(event["DestPort"]))

    if dest_info:
        parts.append("targeting " + ", ".join(dest_info))

    # Logon Type (replacing privileges)
    if event.get("LogonType"):
        parts.append("via logon type {}".format(event["LogonType"]))

    # Final sentence
    if parts:
        return "This event is from " + " ".join(parts) + "."

# Dictonary
def dictionary(event_data):
    event=modifydata(event_data)
     # Core mapping (common fields)
    base_keys = {
        "event_id": "EventID",
        "event_category": "Category",
        "event_type": "EventType",
        "host": "Hostname",
        # "event_message": "Message",
        "source_account_name": "SubjectUserName",
        "source_account_domain": "SubjectDomainName",
        "source_account_sid": "SubjectUserSid",
        "source_logon_id": "SubjectLogonId",
        "source_ip": "SourceAddress",
        "source_port": "SourcePort",
        "source_workstation": "SourceName",
        "source_modulename": "SourceModuleName",
        "event_level": "SeverityValue",
        "event_severity": "Severity"
    }

    # Optional fields
    optional_keys = {
        "destination_account_name": "TargetUserName",
        "destination_account_domain": "TargetDomainName",
        "destination_account_sid": "TargetUserSid",
        "destination_logon_id": "TargetLogonId",
        "destination_port": "DestPort",
        "destination_ip": "DestAddress",
        "process_id": "ProcessID",
        "process_name": "ProcessName",
        "source_logon_process": "LogonProcessName",
        "logon_type": "LogonType",
        "share_name": "ShareName",
        "share_path": "ShareLocalPath",
        "target_relative_path": "RelativeTargetName",
        "access_mask_hex": "AccessMask",
        "access_list_raw": "AccessList",
        "access_reason_detail": "AccessReason",
        "privileges": "PrivilegeList",
        "applicationname": "Application"
    }

    # Build base dictionary
    event_dict = dict((k, event.get(v)) for k, v in base_keys.items())

    # Add optional fields only if present
    for k, v in optional_keys.items():
        val = event.get(v)
        if val is not None:
            # Convert process_id explicitly to string
            if k == "process_id":
                val = str(val)
            event_dict[k] = val

    return event_dict

