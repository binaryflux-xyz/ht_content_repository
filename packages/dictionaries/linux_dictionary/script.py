import re
import time
from datetime import datetime, timedelta
import calendar

# This function determines if the log qualifies for data processing.
def criteria(metainfo):
    return metainfo.get('provider') == 'Linux' and metainfo.get('group') == 'Security' \
        and metainfo.get('type') == 'System'



def timestamp(event):
    datestring = event.get("timestamp")
    if not datestring:
        return None

    # Always use UTC clock (machine-independent)
    now_utc = datetime.utcnow()
    current_year = now_utc.year
    current_month = now_utc.month

    # Parse syslog timestamp (no year, IST)
    full_datestring = "%d %s" % (current_year, datestring)
    dt_ist = datetime.strptime(full_datestring, "%Y %b %d %H:%M:%S")

    # Year rollover logic (UTC-safe)
    if dt_ist.month > current_month:
        dt_ist = dt_ist.replace(year=current_year - 1)

    # IST → UTC
    dt_utc = dt_ist - timedelta(hours=5, minutes=30)

    # UTC → epoch milliseconds
    return calendar.timegm(dt_utc.timetuple()) * 1000
  

# Extracts user-readable message from event
def message(event):
    raw = event.get("message", "") or ""
    host = event.get("host", "") or ""

    process = ""
    pid = ""
    details = raw

    # Extract process and pid if present like procname[1234]
    if "]" in raw and "[" in raw and raw.index("[") < raw.index("]"):
        try:
            prefix, rest = raw.split("]", 1)
            process = prefix.split("[")[0].strip()
            pid = prefix.split("[")[1].strip()
            details = rest.strip().lstrip(" -").strip()
        except:
            pass

    # Cleanup details by removing punctuation that breaks readability
    details = details.replace(":", " ").strip()

    # Build human readable message
    parts = []

    if process:
        parts.append("The process {} with PID {}".format(process, pid))
    else:
        parts.append("A system component")

    if host:
        parts.append("on the host {}".format(host))

    if details:
        parts.append("recorded the event {}".format(details))
    else:
        parts.append("generated a log entry")

    summary = " ".join(parts)

    # Ensure ending period
    if not summary.endswith("."):
        summary += "."

    return summary


# Dictionary function for structured event data

def dictionary(event):
    raw = event.get("message", "") or ""
    host = event.get("host", "") or ""

    # Initialize fields
    process = ""
    pid = ""
    details = raw
    action = ""
    user = ""
    ruser = ""
    rhost = ""
    ip = ""
    port = ""
    file_path = ""
    command = ""
    uid = ""
    exe_path = ""
    dest_ip = ""
    bytes_out = ""

    # process[PID]:
    m = re.match(r"^([A-Za-z0-9_\-]+)\[(\d+)\]\s*[: ]\s*(.*)$", raw)
    if m:
        process = m.group(1)
        pid = m.group(2)
        details = m.group(3).strip()
    
    # process:
    if not process:
        m = re.match(r"^([A-Za-z0-9_\-]+):\s*(.*)$", raw)
        if m:
            process = m.group(1)
            details = m.group(2).strip()

    # failure trimming
    fail_m = re.search(r"(.*?failure)", details, re.IGNORECASE)
    if fail_m:
        details = fail_m.group(1).strip()

    # file path
    m = re.search(r"(/[^ \"']+)", raw)
    if m:
        file_path = m.group(1)

    # UID extraction (lowercase)
    m = re.search(r"\buid=(\d+)", raw)
    if m:
        uid = m.group(1)

    # UID extraction (uppercase — NEW, safe)
    if not uid:
        m = re.search(r"\bUID=(\d+)", raw)
        if m:
            uid = m.group(1)

    # pid= extraction
    if not pid:
        m = re.search(r"\bpid=(\d+)", raw)
        if m:
            pid = m.group(1)

    # auditd executable path
    m = re.search(r"\bexe=([^\s]+)", raw)
    if m:
        exe_path = m.group(1)

    # full cmd extraction
    m = re.search(r"\bcmd=(.*?)(?=\s+exe=|\s*$)", raw)
    if m:
        command = m.group(1).strip()

    # USER=
    m = re.search(r"\bUSER=([A-Za-z0-9_\-]+)", raw)
    if m:
        user = m.group(1)

    # SSH login
    if not user:
        m = re.search(r"\bfor\s+([A-Za-z0-9_\-]+)\s+from\b", raw)
        if m:
            user = m.group(1)

    # NEW: useradd username extraction (before fallback)
    if not user and process == "useradd":
        m = re.search(r"name=([A-Za-z0-9_\-]+)", raw)
        if m:
            user = m.group(1)

    # generic fallback
    if not user:
        m = re.search(r"user\s*\(?([A-Za-z0-9_\-]+)\)?", raw)
        if m:
            user = m.group(1)

    # remote user/host
    m = re.search(r"ruser=([A-Za-z0-9_\-]+)", raw)
    if m:
        ruser = m.group(1)

    m = re.search(r"rhost=([A-Za-z0-9_\.\-]+)", raw)
    if m:
        rhost = m.group(1)

    # generic IP extraction
    m = re.search(r"(\d+\.\d+\.\d+\.\d+)", raw)
    if m:
        ip = m.group(1)

    # destination IP from scp/rsync
    m = re.search(r"@(\d+\.\d+\.\d+\.\d+):", raw)
    if m:
        dest_ip = m.group(1)

    # reverse shell /dev/tcp destination
    m = re.search(r"/dev/tcp/(\d+\.\d+\.\d+\.\d+)/", raw)
    if m:
        dest_ip = m.group(1)
        ip = ""

    # netflow SRC override
    m = re.search(r"\bSRC=(\d+\.\d+\.\d+\.\d+)", raw)
    if m:
        ip = m.group(1)

    # netflow destination
    m = re.search(r"\bDST=(\d+\.\d+\.\d+\.\d+)", raw)
    if m:
        dest_ip = m.group(1)

    # netflow bytes
    m = re.search(r"\bBYTES_OUT=(\d+)", raw)
    if m:
        bytes_out = m.group(1)

    # port
    m = re.search(r"port\s+(\d+)", raw)
    if m:
        port = m.group(1)

    # backward compatible command formats
    m = re.search(r"COMMAND=([^\s]+)", raw)
    if not command and m:
        command = m.group(1)

    m = re.search(r"CMDEND\s*\((.*)\)", raw)
    if not command and m:
        command = m.group(1)

    m = re.search(r"CMD\s*\((.*)\)", raw)
    if not command and m:
        command = m.group(1)

    # action detection
    m = re.search(r"\b(Started|Deactivated|Accepted|Failed|failure|opened|closed|denied|authentication|USER_CMD)\b", raw, re.IGNORECASE)
    if m:
        action = m.group(1)

    # NEW: improve action for useradd only
    if process == "useradd":
        action = "user_created"

    if process == "netflow":
        action = "network_flow"

    # fallback action
    if not action:
        words = details.split()
        if words:
            action = words[0]

    event_dict = {}

    if host: event_dict["host"] = host
    if process: event_dict["process_name"] = process
    if pid: event_dict["process_id"] = pid
    if action: event_dict["event_action"] = action
    if details: event_dict["event_details"] = details
    if ip: event_dict["source_ip"] = ip
    if dest_ip: event_dict["destination_ip"] = dest_ip
    if port: event_dict["source_port"] = port
    if user: event_dict["user"] = user
    if command: event_dict["process_command"] = command
    if file_path: event_dict["file_path"] = file_path
    if ruser: event_dict["remote_user"] = ruser
    if rhost: event_dict["remote_host"] = rhost
    if uid: event_dict["user_id"] = uid
    if exe_path: event_dict["executable"] = exe_path
    if bytes_out: event_dict["network_bytes_out"] = bytes_out

    return event_dict