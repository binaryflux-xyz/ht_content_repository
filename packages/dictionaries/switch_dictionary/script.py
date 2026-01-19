# -*- coding: utf-8 -*-
import re
import time
from datetime import datetime

def criteria(metainfo):
    return metainfo.get('provider') == 'Cisco' and metainfo.get('group') == 'Switch' \
        and metainfo.get('type') == 'Network Logs'

def timestamp(event):
    if "timestamp" not in event or not event["timestamp"]:
        return int(time.time() * 1000)
    else:
        try:
            current_year = datetime.now().year
            datestring = "%d %s" % (current_year, event["timestamp"])
            try:
                dt = datetime.strptime(datestring, "%Y %b %d %H:%M:%S.%f")
            except ValueError:
                dt = datetime.strptime(datestring, "%Y %b %d %H:%M:%S")
            epoch_time = time.mktime(dt.timetuple()) + (dt.microsecond / 1000000.0)
            return int(epoch_time * 1000)
        except Exception:
            return int(time.time() * 1000)

def message(event):
    parts = []
    if event.get("message"):
        parts.append(event["message"])
    if event.get("uptime"):
        parts.append("with uptime {}".format(event["uptime"]))
    if event.get("facility"):
        parts.append("and facility {}".format(event["facility"]))
    return " ".join(parts) + "."

def dictionary(event):
    msg = event.get("message", "")
    event_dict = {
        "event_severity": event.get("severity"),
        "event_sequence_number": event.get("sequence"),
        "event_code": event.get("mnemonic"),
        "event_facility": event.get("facility"),
        "event_details": msg,
    }

    # If uptime is present (like in ILPOWER, LOGIN, or LOGOUT logs)
    if "uptime" in event and event.get("uptime"):
        match = re.search(r"[Ii]nterface\s+([A-Za-z]+\d+\/\d+\/\d+)", msg)
        if match:
            event_dict["event_interface"] = match.group(1)

        power_status = re.search(r"reports\s+power\s+([A-Za-z0-9\s]+)\s+error", msg)
        if power_status:
            event_dict["event_power_error"] = power_status.group(1).strip()

        user = re.search(r"user[:\s]+([A-Za-z0-9_.\-]+)", msg, re.IGNORECASE)
        src_ip = re.search(r"from\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", msg)
        if not src_ip:
            src_ip = re.search(r"\[Source:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]", msg)

        if user:
            event_dict["user_name"] = user.group(1)
        if src_ip:
            event_dict["source_ip"] = src_ip.group(1)

        logout = re.search(
            r"User\s+([A-Za-z0-9\-_]+)\s+has exited tty session\s+(\d+)\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)",
            msg)
        if logout:
            event_dict["user_name"] = logout.group(1)
            event_dict["source_ip"] = logout.group(3)
            event_dict["event_status"] = "Exited"

        if re.search(r"Login\s+Success", msg, re.IGNORECASE):
            event_dict["event_status"] = "Succeeded"

        return event_dict

    # Else branch → SSH2_USERAUTH, SSH2_CLOSE, LOGIN_SUCCESS (timestamp only), etc.
    else:
        # --- EXTENDED REGEX COVERAGE STARTS HERE ---
        # user name formats: "User 'meraki-user'", "for user 'meraki-user'", or "[user: meraki-user]"
        user = re.search(r"User '([^']+)'", msg)
        if not user:
            user = re.search(r"for user '([^']+)'", msg)
        if not user:
            user = re.search(r"\[user:\s*([A-Za-z0-9_.\-]+)\]", msg, re.IGNORECASE)

        # IP address formats: "from 18.235.544.158" or "[Source: 18.235.544.158]"
        src_ip = re.search(r"from\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", msg)
        if not src_ip:
            src_ip = re.search(r"\[Source:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]", msg)

        # Encryption + HMAC
        cipher = re.search(r"cipher\s+'([^']+)'", msg)
        hmac = re.search(r"hmac\s+'([^']+)'", msg)

        # Event status (Succeeded / Failed / Closed)
        status = re.search(r"(Succeeded|Failed|Closed)", msg, re.IGNORECASE)

        # Add support for SSH session request lines
        if not status and "Session request" in msg:
            status = re.search(r"Session request.*?(Succeeded|Failed|Closed)", msg, re.IGNORECASE)

        # Logout pattern (timestamp logs)
        logout = re.search(
            r"User\s+([A-Za-z0-9\-_]+)\s+has exited tty session\s+(\d+)\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)",
            msg)
        if logout:
            event_dict["user_name"] = logout.group(1)
            event_dict["source_ip"] = logout.group(3)
            event_dict["event_status"] = "Exited"

        # Fill extracted fields
        if user:
            event_dict["user_name"] = user.group(1)
        if src_ip:
            event_dict["source_ip"] = src_ip.group(1)
        if cipher:
            event_dict["network_encryption"] = cipher.group(1)
        if hmac:
            event_dict["network_authentication"] = hmac.group(1)
        if status:
            event_dict["event_status"] = status.group(1).capitalize()

        return event_dict