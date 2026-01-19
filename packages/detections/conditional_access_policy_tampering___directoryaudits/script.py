# ------------------------------------------------------------
# Conditional Access Policy Modification Detection
# ------------------------------------------------------------

CA_POLICY_EVENTS = {
    "Add conditional access policy",
    "Update conditional access policy",
    "Delete conditional access policy"
}

# Security admin UPNs allowed to modify CA policies
AUTHORIZED_SECURITY_ADMINS = [
    "secadmin@domain.com",
    "security.team@domain.com"
]

# High-risk groups to protect (cannot be excluded)
HIGH_RISK_GROUPS = [
    "Global Administrators",
    "Privileged Role Administrators",
    "VIP"
]


# ---------------------- Helper Functions ---------------------- #

def _is_authorized_security_admin(upn):
    if not upn:
        return False
    upn_l = upn.lower()
    return upn_l in [a.lower() for a in AUTHORIZED_SECURITY_ADMINS]


def _change_has_itsm_ticket(event):
    """
    Your enrichment layer may add:
       event['change_ticket'] = "INC12345" or None
    """
    ticket = event.get("change_ticket")
    return bool(ticket and ticket not in ["", None, "UNKNOWN"])


def _policy_targets_all_users(event):
    """
    Example:
      change_property_name = 'UserCondition'
      change_new_value contains 'All'
    """
    new_val = str(event.get("change_new_value") or "").lower()
    return "all" in new_val


def _weakens_mfa(event):
    """
    Look for disabling MFA enforcement or policy relaxations.
    """
    new_val = str(event.get("change_new_value") or "").lower()

    risky_terms = [
        "mfa", "multifactor", "requiremultifactor",
        "conditionalaccess", "authenticationstrength"
    ]

    # If MFA-related terms occur AND new value suggests weakening:
    if any(term in new_val for term in risky_terms):
        if any(bad in new_val for bad in ["disabled", "false", "none", "notrequired"]):
            return True

    return False


def _excludes_high_risk_group(event):
    new_val = str(event.get("change_new_value") or "").lower()
    for grp in HIGH_RISK_GROUPS:
        if grp.lower() in new_val and ("exclude" in new_val or "not" in new_val):
            return True
    return False


def window():
    return None


def groupby():
    return None


def investigate():
    return "conditional_access_policy_change_review"


def automate():
    return True


# ---------------------- Algorithm ---------------------- #

def algorithm(event):

    score = 0.0
    valid = True

    actor = event.get("source_email")
    activity = event.get("event_subtype")

    # 1. Must be a CA policy modification
    if activity not in CA_POLICY_EVENTS:
        valid = False

    # 2. Exclude authorized security admins
    elif _is_authorized_security_admin(actor):
        valid = False

    # 3. Suppress if approved ITSM ticket exists
    elif _change_has_itsm_ticket(event):
        valid = False

    # 4. Detect if the change weakens security
    risk_all_users = _policy_targets_all_users(event)
    risk_mfa = _weakens_mfa(event)
    risk_group_exclusion = _excludes_high_risk_group(event)

    # ---------------- Final Single-Return Scoring ---------------- #
    if valid:
        # High severity if CA policy weakened severely
        if risk_mfa or risk_group_exclusion or risk_all_users:
            score = 0.90
        else:
            score = 0.75

    return score


# ---------------------- Context ---------------------- #

def context(event):
    actor = event.get("source_account_name")
    actor_email = event.get("source_email")
    activity = event.get("event_subtype")
    policy = event.get("destination_object_name")
    src_ip = event.get("source_ip")
    old_v = event.get("change_old_value")
    new_v = event.get("change_new_value")

    msg = (
        "A conditional access policy modification was detected. "
        "Actor '{actor}' ({actor_email}) performed '{activity}' on policy '{policy}'. "
        "The policy changed from '{old}' to '{new}'. Source IP: {ip}. "
        "This may indicate tampering with authentication or MFA enforcement."
    ).format(
        actor=actor,
        actor_email=actor_email,
        activity=activity,
        policy=policy,
        old=old_v,
        new=new_v,
        ip=src_ip
    )

    return msg


# ---------------------- Metadata ---------------------- #

def criticality():
    return "HIGH"


def tactic():
    return "Defense Evasion (TA0005)"


def technique():
    return "Modify Authentication Mechanisms (T1556)"


def artifacts():
    return stats.collect([
        "source_email",
        "source_account_name",
        "destination_object_name",
        "event_subtype",
        "change_property_name",
        "change_old_value",
        "change_new_value",
        "source_ip",
        "change_ticket"
    ])


def entity(event):
    return {"derived": False, "value": event.get("destination_object_name"), "type": "conditionalaccesspolicy"}
