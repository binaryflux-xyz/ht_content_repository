import time
from datetime import datetime

def window():
    return None

def groupby():
    return []

def investigate():
    return "session_analyser"

# def automate():
#     return False

def init(event):
  session.set("event", event)
  return "initializee"

def timestamp(event):
    ts = event.get("created_timestamp")

    ts = ts.split(".")[0].replace("Z", "")

    dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")

    epoch_sec = int(time.mktime(dt.timetuple()))

    # convert to milliseconds
    return epoch_sec * 1000


def algorithm(event):
    print("algorithm")
    resolution = event.get("resolution")
  
    if resolution == 'false_postive' or resolution == 'ignored':
        return 0.0
    print("resolution",resolution)
    criticality = event.get("severity_name")
    print("criticality",criticality)
    if criticality == 'Low':
        return 0.25
      
    if criticality == 'Informational':
        return 0.25
      
    if criticality == 'High':
        return 0.75
      
    if criticality == 'Critical':
        return 1.0
    
    return 0.50
    
def context(event):
    device = event.get("device") or {}
    parent = event.get("parent_details") or {}
    net = event.get("network_accesses") or []

    alert = event.get("display_name") or event.get("name") or "Security detection"
    severity = event.get("severity_name") or event.get("severity") or "unknown"
    host = device.get("hostname")
    user = event.get("user_name")
    process = event.get("filename")
    filepath = event.get("filepath")
    quarantined = event.get("quarantined")
    desc = event.get("description")

    dst_ip = None
    for n in net:
        if not isinstance(n, dict):
            continue
        ip = n.get("remote_address")
        if ip and "." in str(ip):
            dst_ip = ip
            break

    parts = []

    parts.append("The %s detected" % alert)

    if process:
        parts.append("for executable %s" % process)

    if filepath:
        parts.append("at %s" % filepath)

    if host:
        parts.append("on host %s" % host)

    if user:
        parts.append("by user %s" % user)

    parent_name = parent.get("filename")
    if parent_name:
        parts.append("spawned via %s" % parent_name)

    if dst_ip:
        parts.append("with connection to %s" % dst_ip)

    if quarantined is True:
        parts.append("and was quarantined")
    elif quarantined is False:
        parts.append("and was not quarantined")

    if severity:
        parts.append("(criticality: %s)" % severity)

    summary = " ".join(parts) + "."

    if desc:
        summary += " " + desc
    else:
        # fallback behavior wording
        summary += " This activity may indicate potentially malicious behavior and requires review."

    return summary

def criticality():
    event = session.get("event", {})
    severity = event.get("severity_name")

    if not severity:
        return "MEDIUM"

    severity = severity.lower()

    if severity == "informational":
        return "LOW"
    elif severity in ["low"]:
        return "LOW"
    elif severity in ["medium"]:
        return "MEDIUM"
    elif severity in ["high"]:
        return "HIGH"
    elif severity in ["critical"]:
        return "CRITICAL"

    return "MEDIUM"

  
def tactic():
    event = session.get("event")

    t_name = event.get("tactic")
    t_id = event.get("tactic_id")

    if not t_name or not t_id:
        mitre = event.get("mitre_attack") or []
        if mitre:
            first = mitre[0] or {}
            t_name = first.get("tactic")
            t_id = first.get("tactic_id")

    if t_id:
        t_id = str(t_id)
        if t_id.startswith("CS"):
            t_id = t_id[2:]

    if t_name and t_id:
        return "%s (%s)" % (t_name, t_id)

    return None

def technique():
    event = session.get("event")

    tech_name = event.get("technique")
    tech_id = event.get("technique_id")

    if not tech_name or not tech_id:
        mitre = event.get("mitre_attack") or []
        if mitre:
            first = mitre[0] or {}
            tech_name = first.get("technique")
            tech_id = first.get("technique_id")

    if tech_id:
        tech_id = str(tech_id)
        if tech_id.startswith("CS"):
            tech_id = tech_id[2:]

    if tech_name and tech_id:
        return "%s (%s)" % (tech_name, tech_id)

    return None

def artifacts():
    event = session.get("event")
    device = event.get("device") or {}
    parent = event.get("parent_details") or {}
    net = event.get("network_accesses") or []

    out = {}

    def add(key, val):
        if val is None:
            return
        if isinstance(val, list):
            vals = [str(v) for v in val if v]
        else:
            vals = [str(val)]

        if not vals:
            return

        if key not in out:
            out[key] = []

        out[key].extend(vals)
        out[key] = list(set(out[key]))

    add("host_id", device.get("device_id"))
    add("host", device.get("hostname"))
    add("os_name", device.get("platform_name") or event.get("platform"))
    add("os_version", device.get("os_version"))
    add("source_mac_address", device.get("mac_address"))
    add("destination_city", device.get("site_name"))
    add("device_groups", device.get("groups"))
    add("host_domain", device.get("hostinfo", {}).get("domain"))
    add("device_type", device.get("product_type_desc"))

    add("user_id", event.get("user_id"))
    add("user", event.get("user_name"))
    add("user_sid", event.get("user_sid"))
    add("user_type", event.get("account_type"))
    add("target_user", event.get("target_account"))

    add("process_id", event.get("process_id"))
    add("process_name", event.get("filename"))
    add("process_path", event.get("filepath"))
    add("command_line", event.get("cmdline"))
    add("local_process_id", event.get("local_process_id"))

    add("parent_process_id", parent.get("process_id"))
    add("parent_process_name", parent.get("filename"))
    add("parent_process_path", parent.get("filepath"))
    add("parent_command_line", parent.get("cmdline"))
    add("parent_process_hash", parent.get("sha256") or parent.get("md5"))

    add("file_name", event.get("filename"))
    add("file_path", event.get("filepath"))
    add("file_hash", event.get("sha256") or event.get("md5"))
    add("file_type", event.get("alleged_filetype"))

    for f in event.get("files_written") or []:
        if isinstance(f, dict):
            add("file_name", f.get("filename"))
            add("file_path", f.get("filepath"))

    for d in event.get("dns_requests") or []:
        if isinstance(d, dict):
            add("domain_name", d.get("domain_name"))

    src_ip = (
        device.get("local_ip")
        or device.get("external_ip")
    )

    if src_ip and "." in str(src_ip):
        add("source_ip", src_ip)
    else:
        # fallback to network list
        for n in net:
            if not isinstance(n, dict):
                continue
            local_ip = n.get("local_address")
            if local_ip and "." in str(local_ip):
                add("source_ip", local_ip)

    for n in net:
        if not isinstance(n, dict):
            continue

        remote_ip = n.get("remote_address")

        if remote_ip and "." in str(remote_ip):
            add("destination_ip", remote_ip)

        add("source_port", n.get("local_port"))
        add("destination_port", n.get("remote_port"))
        add("network_protocol", n.get("protocol"))
        add("network_direction", n.get("connection_direction"))

    add("auth_type", event.get("auth_type"))
    add("logon_type", event.get("logon_type"))
    add("auth_result", event.get("auth_result"))
    add("source_host", event.get("source_host"))
    add("target_host", event.get("target_host"))

    add("event_status", event.get("status"))
    add("alert_name", event.get("scenario"))
    add("threat_objective", event.get("objective"))
    add("file_global_prevalence", event.get("global_prevalence"))
    add("file_local_prevalence", event.get("local_prevalence"))

    return out 

def entity(event):
    if "events" in event and event["events"]:
        event = event["events"][0]

    device = event.get("device", {})
    return {
        "derived": False,
        "value": device.get("hostname"),
        "type": "host"
    }
