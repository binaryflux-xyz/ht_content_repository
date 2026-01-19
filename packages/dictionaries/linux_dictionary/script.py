import time
from datetime import datetime

# This function determines if the log qualifies for data processing.
def criteria(metainfo):
    return metainfo.get('provider') == 'Linux' and metainfo.get('group') == 'OS Events' \
        and metainfo.get('type') == 'Security'

def timestamp(event):
    datestring = event.get("EventTime")
    dt = datetime.strptime(datestring, "%Y-%m-%d %H:%M:%S")  # Parse the string to datetime
    epoch_time = time.mktime(dt.timetuple())  # Convert to seconds since epoch
    milliseconds = int(epoch_time * 1000)  # Convert to milliseconds
    return milliseconds

# Extracts user-readable message from event
def message(event):
    parts = []

    # Severity
    if event.get("SyslogSeverity"):
        parts.append("Security event with severity '{}'".format(event["SyslogSeverity"]))
    else:
        parts.append("A Linux security event occurred")

    # Host
    if event.get("Hostname"):
        parts.append("on host {}".format(event["Hostname"]))

    # Process info
    if event.get("SourceName"):
        parts.append("triggered by process '{}'".format(event["SourceName"]))
    if event.get("ProcessID"):
        parts.append("(PID {})".format(event["ProcessID"]))

    # User / IP context
    if event.get("MessageSourceAddress"):
        parts.append("from IP {}".format(event["MessageSourceAddress"]))

    # Event message
    if event.get("Message"):
        parts.append("details: {}".format(event["Message"]))

    # Final sentence
    if parts:
        return " ".join(parts) + "."
    else:
        return "Linux OS security event details are unavailable."

# Dictionary function for structured event data
def dictionary(event):
    event_dict = {
        "event_time": event.get("EventReceivedTime"),
        "event_severity_value": event.get("SyslogSeverityValue"),
        "event_severity_type": event.get("SyslogSeverity"),
        "event_category": event.get("SourceModuleName"),
        "source_file": event.get("SourceModuleType"),
        "source_type": event.get("SyslogFacility"),
        "source_type_value": event.get("SyslogFacilityValue"),
        "host": event.get("Hostname"),
        "action": event.get("SourceName"),
        "process_id": event.get("ProcessID"),
        "event_message": event.get("Message"),
        "user_ip": event.get("MessageSourceAddress"),
    }

    return event_dict





  