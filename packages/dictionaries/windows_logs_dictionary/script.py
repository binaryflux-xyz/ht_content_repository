# -*- coding: utf-8 -*-
import json
import time
from datetime import datetime, timedelta
import re

def criteria(metainfo):
    return (
        metainfo['provider'] == 'Microsoft'
        and metainfo['group'] == 'Windows Events'
        and metainfo['type'] == 'Audit'
    )


def clean_dict(d):
    cleaned = {}
    for k, v in d.items():
        if v is None:
            continue

        # Case 1: list
        if isinstance(v, list):
            valid_items = [x for x in v if isinstance(x, basestring) and x.strip() not in ["-", "_"]]
            if valid_items:
                cleaned[k] = v
            continue

        # Case 2: string
        if isinstance(v, basestring):
            v = v.strip()
            if v in ["-", "_"]:
                continue

        cleaned[k] = v
    return cleaned


def timestamp(data):
    log_str = data.get("log")
    try:
        event = json.loads(log_str)
    except ValueError as e:
        print("❌ JSON Decode Error: {}".format(str(e)))
        print("🔹 Problematic log_str (raw):")
        print(log_str)
        return None

    datestring = event.get("EventTime")
    if not datestring:
        return None

    dt_ist = datetime.strptime(datestring, "%Y-%m-%d %H:%M:%S")
    dt_utc = dt_ist - timedelta(hours=5, minutes=30)
    epoch_time = time.mktime(dt_utc.timetuple()) + dt_utc.microsecond / 1e6
    return int(epoch_time * 1000)


def modifydata(json_data):
    if "PrivilegeList" in json_data:
        privileges = re.split(r"\s+", json_data["PrivilegeList"].strip())
        json_data["PrivilegeList"] = [priv for priv in privileges if priv]
    return json_data


def message(data):
    log_str = data.get("log")
    event = json.loads(log_str)
    parts = []

    if event.get("Hostname"):
        parts.append("host {}".format(event["Hostname"]))
    if event.get("EventID"):
        parts.append("event ID {}".format(event["EventID"]))
    if event.get("SubjectUserName"):
        parts.append("initiated by account name {}".format(event["SubjectUserName"]))
    if event.get("IpAddress"):
        parts.append("from IP {}".format(event["IpAddress"]))
    if event.get("ProcessName"):
        parts.append("running process {}".format(event["ProcessName"]))
    if event.get("Severity"):
        parts.append("with severity {}".format(event["Severity"]))

    dest_info = []
    if event.get("TargetUserName"):
        dest_info.append("user {}".format(event["TargetUserName"]))
    if event.get("DestAddress"):
        dest_info.append("at destination IP {}".format(event["DestAddress"]))
    if event.get("DestPort"):
        dest_info.append("on port {}".format(event["DestPort"]))

    if dest_info:
        parts.append("targeting " + ", ".join(dest_info))
    if event.get("LogonType"):
        parts.append("via logon type {}".format(event["LogonType"]))

    if parts:
        return "This event is from " + " ".join(parts) + "."


# ------------------------------------------------------------------------
#  Optimized Drop-in Replacement for dictionary()
# ------------------------------------------------------------------------
def dictionary(data):
    log_str = data.get("log")
    if not log_str:
        return {}

    try:
        event = json.loads(log_str)
    except ValueError:
        return {}

    event = modifydata(event)
    get = event.get
    ad = dict.__setitem__

    event_dict = {}

    # --- Core fields ---
    mapping = [
        (["EventID"], "event_id"),
        (["Category"], "event_category"),
        (["EventType"], "event_type"),
        (["Hostname"], "host"),
        (["Message"], "event_message"),
    ]

    # --- Extended / optional fields ---
    mapping.extend([
        (["TargetUserSid"], "destination_account_sid"),
        (["TargetUserName"], "destination_account_name"),
        (["TargetDomainName"], "destination_account_domain"),
        (["TargetLogonId"], "destination_logon_id"),
        (["DestPort"], "destination_port"),
        (["DestAddress"], "destination_ip"),
        (["SubjectUserName"], "source_account_name"),
        (["SubjectDomainName"], "source_account_domain"),
        (["SubjectUserSid"], "source_account_sid"),
        (["SubjectLogonId"], "source_logon_id"),
        (["IpAddress"], "source_ip"),
        (["IpPort"], "source_port"),
        (["SourceName"], "source_workstation"),
        (["SourceModuleName"], "source_modulename"),
        (["SeverityValue"], "event_level"),
        (["Severity"], "event_severity"),
        (["Channel"], "event_channel"),
        (["LogonType"], "logon_type"),
        (["AuthenticationPackageName"], "source_authentication_package"),
        (["ElevatedToken"], "source_elevated_token"),
        (["LogonProcessName"], "source_logon_process"),
        (["ShareName"], "share_name"),
        (["ShareLocalPath"], "share_path"),
        (["RelativeTargetName"], "target_relative_path"),
        (["AccessMask"], "access_mask_hex"),
        (["AccessList"], "access_list_raw"),
        (["AccessReason"], "access_reason_detail"),
        (["PrivilegeList"], "privileges"),
        (["ServiceName"], "service_name"),
        (["ImagePath"], "service_binary_path"),
        (["ServiceAccount"], "service_account"),
        (["StartType"], "service_start_type"),
        (["ParentProcessName"], "parent_process_name"),
        (["Process Command Line"], "command_line"),
    ])

    # --- Populate in one pass ---
    for srcs, dest in mapping:
        for src in srcs:
            val = get(src)
            if val not in (None, "-", "_", "UNKNOWN", ""):
                ad(event_dict, dest, val)
                break

    # --- Process name logic (preserve original behavior) ---
    process_name = get("ProcessName")
    new_process_name = get("NewProcessName")
    if process_name and process_name.strip() not in ["-", "_"]:
        event_dict["source_process_name"] = process_name
    elif new_process_name and new_process_name.strip() not in ["-", "_"]:
        event_dict["source_process_name"] = new_process_name

    return clean_dict(event_dict)