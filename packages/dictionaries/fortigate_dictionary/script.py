# -*- coding: utf-8 -*-
import calendar
import re
from datetime import datetime, timedelta

IST_OFFSET = timedelta(hours=5, minutes=30)

INVALID_VALUES = frozenset(("-", "_", ""))

_TOKEN_RE = re.compile(r'([a-zA-Z0-9_]+)\s*=\s*(".*?"|[^"\s,]+)')

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

# --- Flatten mapping ---
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
    (["error"], "alert_name"),
    (["level"], "event_level"),
    (["severity"], "event_severity"),
    (["remip"], "source_remote_ip"),
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
    (["dstip"], "destination_ip"),
    (["dstport"], "destination_port"),
    (["dstintf"], "destination_device_interface"),
    (["dstintfrole"], "destination_device_interface_role"),
    (["dstcountry"], "destination_country"),
    (["qname"], "destination_hostname"),
    (["dstcity"], "destination_city"),
    (["dstregion"], "destination_region"),
    (["dstdevtype"], "destination_device_type"),
    (["user"], "user"),
    (["group"], "user_group"),
    (["profile"], "user_role"),
    (["agent"], "user_agent"),
    (["osname"], "os_name"),
    (["service"], "network_protocol"),
    (["dir", "direction"], "network_direction"),
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
    (["url"], "url"),
]

_MAPPING_LOOKUP = {}
for sources, dest in _MAPPING_TABLE:
    for s in sources:
        _MAPPING_LOOKUP[s] = dest

def init(old_event):
    # parsed = parse_kv_line(old_event)
    session.set("event", old_event)
    return "initialized"


def criteria(metainfo):
    return (
        metainfo.get('provider') == 'Fortigate'
        and metainfo.get('group') == 'Firewall'
        and metainfo.get('type') == 'Network'
    )


# ✅ Optimized parser (same behavior, less CPU)
def parse_kv_line(data):
    parsed = data.copy() if isinstance(data, dict) else {}
    line = data.get("Message", "")

    if not isinstance(line, basestring):
        try:
            line = line.decode("utf-8", "replace")
        except AttributeError:
            line = str(line)

    for key, value in _TOKEN_RE.findall(line):

        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]

        if key in parsed and key != "msg":
            existing = parsed[key]
            if not isinstance(existing, list):
                parsed[key] = [existing, value]
            else:
                existing.append(value)
        else:
            parsed[key] = value

    return parsed


def clean_dict(d):
    cleaned = {}
    _invalid = INVALID_VALUES

    for k, v in d.iteritems():

        if v is None:
            continue

        if isinstance(v, list):
            new_list = []
            for x in v:
                if isinstance(x, basestring):
                    x = x.strip()
                    if x not in _invalid:
                        new_list.append(x)
            if new_list:
                cleaned[k] = new_list
            continue

        if isinstance(v, basestring):
            v = v.strip()
            if v in _invalid:
                continue

        cleaned[k] = v

    return cleaned

def timestamp(event):
    event = session.get("event")

    date_str = event.get("date")
    time_str = event.get("time")
    event_type = event.get("type")
    devname = event.get("devname")

    if not date_str or not time_str:
        print("---------------------------------------------------------------------")
        print("if not date_str = {0} or not time_str = {1}".format(date_str,time_str))
        return None

    if devname and "=" in devname:
        print("---------------------------------------------------------------------")
        print("if devname and '=' in devname")
        return None

    try:
        y, m, d = map(int, date_str.split("-"))
        hh, mm, ss = map(int, time_str.split(":"))
        dt = datetime(y, m, d, hh, mm, ss)
    except:
        print("---------------------------------------------------------------------")
        print("except")
        return None

    dt_utc = dt - IST_OFFSET
    return int(calendar.timegm(dt_utc.timetuple()) * 1000)


def message(event_data):
    event = session.get("event")
    get = event.get

    parts = []
    append = parts.append

    action = get("action")
    text = ("The firewall with action %s " % action) if action else "The firewall recorded an event "

    attack = get("attack") or get("logdesc")
    if attack:
        text += "related to %s " % attack

    append(text.strip())

    src_parts = []
    if get("user"):
        src_parts.append("user %s" % event["user"])
    if get("srcip"):
        src_parts.append("IP %s" % event["srcip"])
    if get("srcport"):
        src_parts.append("port %s" % event["srcport"])
    if src_parts:
        append("from source %s" % ", ".join(src_parts))

    dst_parts = []
    if get("dstip"):
        dst_parts.append("IP %s" % event["dstip"])
    if get("dstport"):
        dst_parts.append("port %s" % event["dstport"])
    if get("qname"):
        dst_parts.append("host %s" % event["qname"])
    if dst_parts:
        append("to destination %s" % ", ".join(dst_parts))

    app = get("app")
    if app:
        append("using application %s" % app)

    service = get("service")
    if service:
        srv = str(service)
        if "/" in srv:
            srv = srv.split("/", 1)[0]
        append("and using %s" % srv)

    if get("severity"):
        append("with severity %s" % event["severity"])
    if get("status"):
        append("status was %s" % event["status"])

    return " ".join(parts) + "." if parts else "Firewall event details unavailable."


def to_int(value):
    if value is None:
        return None
    try:
        return int(float(value))
    except:
        return None


def dictionary(event_data):
    event = session.get("event")
    event_dict = {}
    _invalid = INVALID_VALUES

    for src, val in event.iteritems():
        if src in _MAPPING_LOOKUP and val and val not in _invalid:
            dest = _MAPPING_LOOKUP[src]

            if dest in ("policy_id", "user"):
                val = str(val)

            elif dest == "network_protocol":
                val_str = str(val)
                if "/" in val_str:
                    val = val_str.split("/", 1)[0]

            event_dict[dest] = val

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