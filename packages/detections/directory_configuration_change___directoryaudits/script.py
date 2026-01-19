# ------------------------------------------------------------
# Directory Setting / Security Configuration Change Detection
# ------------------------------------------------------------

DIRECTORY_SETTING_EVENTS = {
    "Update organization",
    "Update directory setting",
    "Update tenant settings"
}

# Known automation/configuration accounts
CONFIG_AUTOMATION_ACCOUNTS = [
    "config-bot@domain.com",
    "automation@domain.com",
    "sync-engine@domain.com"
]

# High-risk configuration properties
HIGH_RISK_PROPERTIES = [
    "securitydefaultsenabled",
    "federationsettings",
    "passwordpolicies",
    "authenticationmethods",
    "authenticationflows"
]




# ------------------ Helper Functions ------------------ #

def _is_config_automation(upn):
    if not upn:
        return False
    upn_l = upn.lower()
    return upn_l in [a.lower() for a in CONFIG_AUTOMATION_ACCOUNTS]


def _is_high_risk_property(event):
    prop = str(event.get("change_property_name") or "").lower()
    return any(h in prop for h in HIGH_RISK_PROPERTIES)


def _has_itsm_ticket(event):
    """
    If event has ITSM ticket field (enrichment),
    example: event['change_ticket'] = "CHG12345"
    """
    ticket = event.get("change_ticket")
    return bool(ticket and ticket not in ["", None, "UNKNOWN"])


def window():
    return None


def groupby():
    return None


def algorithm(event):

    score = 0.0
    valid = True

    actor = event.get("source_email")
    activity = event.get("event_subtype")

    # 1. Must be directory-level configuration activity
    if activity not in DIRECTORY_SETTING_EVENTS:
        valid = False

    # 2. Exclude known automation/configuration accounts
    elif _is_config_automation(actor):
        valid = False

    # 3. Suppress if ITSM change ticket present
    elif _has_itsm_ticket(event):
        valid = False

    # 4. Check if modified property is high-risk
    risky_property = _is_high_risk_property(event)

    # ---------------- Single-Return Scoring ---------------- #

    if valid:
        if risky_property:
            score = 0.90   # High-risk tenant-level change
        else:
            score = 0.75   # Normal directory configuration change

    return score


# ------------------ Context ------------------ #

def context(event):

    actor = event.get("source_account_name")
    actor_email = event.get("source_email")
    activity = event.get("event_subtype")
    prop = event.get("change_property_name")
    old_v = event.get("change_old_value")
    new_v = event.get("change_new_value")
    src_ip = event.get("source_ip")

    return (
        "A directory-wide configuration change was detected. "
        "Actor '{actor}' ({actor_email}) performed '{activity}'. "
        "Modified property '{prop}' changed from '{old}' to '{new}'. "
        "Source IP: {ip}. This may indicate updates to security defaults, "
        "federation settings, or tenant-level authentication policies."
    ).format(
        actor=actor,
        actor_email=actor_email,
        activity=activity,
        prop=prop,
        old=old_v,
        new=new_v,
        ip=src_ip
    )


# ------------------ Metadata ------------------ #

def criticality():
    return "HIGH"


def tactic():
    return "Defense Evasion (TA0005)"


def technique():
    return "Modify Cloud Identity Configurations (T1098.003)"


def artifacts():
    return stats.collect([
        "source_email",
        "source_account_name",
        "event_subtype",
        "change_property_name",
        "change_old_value",
        "change_new_value",
        "source_ip",
        "change_ticket"
    ])


def entity(event):
    # Entity = tenant/directory being modified
    return {"derived": False, "value": "tenant", "type": "directory"}
