# -*- coding: utf-8 -*-
import time
from datetime import datetime, timedelta
import calendar
import re

# --- Static lookup for log levels ---
log_levels = {
    "emergency": 0,
    "alert": 1,
    "critical": 2,
    "error": 3,
    "warning": 4,
    "notice": 5,
    "information": 6,
    "debug": 7
}

# --- Criteria function ---
def criteria(metainfo):
    return (
        metainfo.get('provider') == 'Fortigate'
        and metainfo.get('group') == 'Firewall'
        and metainfo.get('type') == 'Firewall Logs'
    )

# --- Cleaner function ---
def clean_dict(d):
    cleaned = {}
    for k, v in d.items():
        if v is None:
            continue
        if isinstance(v, list):
            valid_items = [x for x in v if isinstance(x, basestring) and x.strip() not in ["-", "_"]]
            if valid_items:
                cleaned[k] = v
            continue
        if isinstance(v, basestring):
            v = v.strip()
            if v in ["-", "_"]:
                continue
        cleaned[k] = v
    return cleaned

# --- Timestamp extractor ---
def timestamp(event):
    ns = event.get("eventtime")
    if ns is None:
        return None
    epoch_ms = ns // 1000000
    return int(epoch_ms)

# --- Key-value parser ---
def parse_kv_line(data):
    parsed = dict(data)
    line = data.get("Message", "")
    if not isinstance(line, str):
        try:
            line = line.decode("utf-8", "replace")
        except AttributeError:
            line = str(line)

    line = re.sub(r'\\\s+(\w+=)', r' \1', line)
    tokens = re.findall(r'(?:[^\s"]+|"[^"]*")+', line)

    for token in tokens:
        if '=' not in token:
            continue
        key, value = token.split('=', 1)
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        if key in parsed and key != 'msg':
            if not isinstance(parsed[key], list):
                parsed[key] = [parsed[key]]
            parsed[key].append(value)
        else:
            parsed[key] = value
    return parsed

# --- Human-readable message generator ---
def message(event_data):
    event = parse_kv_line(event_data)
    parts = []
    if event.get("action"):
        text = "The firewall with action {} ".format(event["action"])
    else:
        text = "The firewall recorded an event "

    if event.get("attack") or event.get("logdesc"):
        text += "related to {} ".format(event.get("attack") or event.get("logdesc"))
    parts.append(text.strip())

    src_parts = []
    if event.get("user"):
        src_parts.append("user {}".format(event["user"]))
    if event.get("srcip"):
        src_parts.append("IP {}".format(event["srcip"]))
    if event.get("srcport"):
        src_parts.append("port {}".format(event["srcport"]))
    if src_parts:
        parts.append("from source {}".format(", ".join(src_parts)))

    dst_parts = []
    if event.get("dstip"):
        dst_parts.append("IP {}".format(event["dstip"]))
    if event.get("dstport"):
        dst_parts.append("port {}".format(event["dstport"]))
    if event.get("qname"):
        dst_parts.append("host {}".format(event["qname"]))
    if dst_parts:
        parts.append("to destination {}".format(", ".join(dst_parts)))

    if event.get("app"):
        app_str = event.get("app")
        parts.append("using application {}".format(app_str))
    if event.get("service"):
        srv = event.get("service")
        if "/" in srv:
            srv = srv.split("/", 1)[0]

        parts.append("and using {}".format(srv))

    if event.get("severity"):
        parts.append("with severity {}".format(event["severity"]))
    if event.get("status"):
        parts.append("status was {}".format(event["status"]))

    if not parts:
        return "Firewall event details unavailable."
    return " ".join(parts) + "."

# --- Optimized mapping table (built once) ---
_MAPPING_TABLE = [
    (["policyname"], "policy_name"),
    (["policyid"], "policy_id"),
    (["policytype"], "policy_type"),
    (["type"], "log_type"),
    (["subtype"], "log_subtype"),
    (["attack", "logdesc"], "event"),
    (["reason", "attack"], "event_alert"),
    (["eventid"], "event_id"),
    (["eventtype"], "event_type"),
    (["duration"], "event_duration"),
    (["cat"], "event_category_id"),
    (["catdesc"], "event_category_desc"),
    (["crlevel"], "alert_severity"),
    (["crscore"], "alert_score"),
    (["dtype"], "alert_type"),
    (["virusid"], "alert_id"),
    (["error"], "alert_name"),
    (["level"], "event_level"),
    (["severity"], "event_severity"),
    (["remip"], "source_remote_ip"),
    (["categoryoutcome"], "event_outcome"),
    (["sessionid"], "event_sessionid"),
    (["action"], "event_action"),
    (["msg"], "event_details"),
    (["Hostname", "hostname"], "host"),
    (["srcip"], "source_ip"),
    (["srcport"], "source_port"),
    (["srcmac"], "source_mac_address"),
    (["srccountry"], "source_country"),
    (["srcintf"], "source_device_interface"),
    (["srcintfrole"], "source_device_interface_role"),
    (["devname"], "source_device_name"),
    (["devid"], "source_device_id"),
    (["devtype"], "source_device_type"),
    (["devcategory"], "source_device_category"),
    (["srcname"], "source_name"),
    (["dstip"], "destination_ip"),
    (["dstport"], "destination_port"),
    (["dstintf"], "destination_device_interface"),
    (["dstintfrole"], "destination_device_interface_role"),
    (["dstcountry"], "destination_country"),
    (["qname"], "destination_hostname"),
    (["dstcity"], "destination_city"),
    (["dstregion"], "destination_region"),
    (["dstdevtype"], "destination_device_type"),
    (["user"], "user_name"),
    (["group"], "user_group"),
    (["profile"], "user_role"),
    (["agent"], "user_agent"),
    (["osname"], "os_name"),
    (["service"], "network_protocol"),
    (["dir", "direction"], "network_direction"),
    (["method"], "network_request_method"),
    (["encryption"], "network_encryption"),
    (["rcvdbyte"], "network_bytes_in"),
    (["sentbyte"], "network_bytes_out"),
    (["rcvdpkt"], "network_packets_in"),
    (["sentpkt"], "network_packets_out"),
    (["status"], "network_status"),
    (["tunneltype"], "tunnel_type"),
    (["app"], "applicationname"),
    (["appcat", "catdesc"], "application_category"),
    (["appid"], "application_id"),
    (["applist"], "application_control_profile"),
    (["apprisk"], "application_risk"),
    (["filename"], "file_name"),
    (["filetype"], "file_extension"),
    (["filesize"], "file_size"),
    (["url"], "url"),
    (["agent"], "user_agent"),
]

def to_int(value):
    try:
        if value is None:
          return None
        return int(float(value))
    except (TypeError, ValueError):
        return None
      
# --- Optimized dictionary creation ---
def dictionary(event_data):
    event = parse_kv_line(event_data)
    get = event.get
    ad = dict.__setitem__
    event_dict = {}

    for sources, dest in _MAPPING_TABLE:
        for src in sources:
            val = get(src)
            if val and val not in ("-", "_", ""):
                if dest == "policy_id":
                    val = str(val)

                if dest == "network_protocol":
                    if "/" in val:
                        val = val.split("/", 1)[0]

                ad(event_dict, dest, val)
                break

    lvl = event_dict.get("event_level")
    if lvl in log_levels:
        event_dict["event_level"] = log_levels[lvl]
      
    event_dict["event_duration"] = to_int(event_dict.get("event_duration"))
    event_dict["event_category_id"] = to_int(event_dict.get("event_category_id"))
    if "destination_port" in event_dict:
        event_dict["destination_port"] = str(event_dict["destination_port"])
    if "source_port" in event_dict:
        event_dict["source_port"] = str(event_dict["source_port"])
  
    return clean_dict(event_dict)