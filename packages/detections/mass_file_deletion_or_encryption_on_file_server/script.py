# Detection: Mass File Deletion / Encryption (File Server PRO-QA-FS01)
# Purpose: Detect ransomware-like mass deletions or mass modifications on the file server PRO-QA-FS01.
# Events: 4663 (An attempt was made to access an object), 4656 (A handle to an object was requested)
# Threshold: >100 delete/modify actions by one user on PRO-QA-FS01 within 10 minutes
# MITRE: Data Encrypted for Impact (T1486) / Impact (TA0040)

def window():
    # 10 minute rolling window
    return '10m'

def groupby():
    # scope per host and user
    return ['account_name']

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
  
WHITELIST_ACCOUNTS = [
    # --- Windows System Accounts ---
    "nt authority\\system",
    "nt authority\\network service",
    "nt authority\\local service",
    "system",
    "localservice",
    "networkservice",

    # --- Backup & Maintenance Accounts ---
    "backupsvc",
    "svc_backup",
    "veeam",
    "veeamagent",
    "commvault",
    "veritas",
    "arcserve",
    "dpmbackup",
    "rubrik",
    "cohesity",

    # --- Antivirus / EDR / Security Agents ---
    "crowdstrike",
    "falcon",
    "carbonblack",
    "sentinelone",
    "defender",
    "sophos",
    "mcafee",
    "trendmicro",
    "symantec",
    "eset",
    "cybereason",

    # --- Patch / Deployment / Configuration Management ---
    "sccm",
    "wsus",
    "intune",
    "pdqdeploy",
    "landesk",
    "altiris",
    "tanium",
    "chef",
    "puppet",
    "ansible",
    "jamf",

    # --- File Sync / Collaboration Services ---
    "onedrive",
    "sharepoint",
    "dropbox",
    "googledrive",
    "nextcloud",
    "owncloud",
    "synology",
    "qnap",

    # --- Common Enterprise Automation Accounts ---
    "svc_filecopy",
    "svc_batch",
    "svc_scheduledtask",
    "svc_filesync",
    "svc_replication",
    "svc_dbbackup",
    "svc_maintenance",
    "svc_monitor",
    "svc_orchestrator",

    # --- Virtualization / Infrastructure Management ---
    "vmtools",
    "vmware",
    "hyperv",
    "vcenter",
    "svc_esxi",
    "svc_vmbackup",

    # --- Cloud or Domain Integration ---
    "azureadconnect",
    "adconnect",
    "azurebackup",
    "gmsa",
    "svc_azureagent",
    "svc_msol",
    "svc_adfs"
]

# Pre-lowercase whitelist once
WHITELIST_LOWER = [w.lower() for w in WHITELIST_ACCOUNTS]


def _is_whitelisted_account(account):
    if not account:
        return False

    an = account.strip().lower()

    # Faster than repeated .lower() calls + substring scanning
    for w in WHITELIST_LOWER:
        if w in an:
            return True

    return False



def _is_destructive_action(event):

    # EventID check stays the same
    evt = str(event.get("event_id", ""))
    if evt not in ("4663", "5145"):
        pass

    # Avoid building one giant string and lowercasing it
    access_raw = str(event.get("access_list_raw") or "").lower()
    access_mask = str(event.get("access_mask_hex") or "").lower()
    access_reason = str(event.get("access_reason_detail") or "").lower()

    destructive_keywords = [
        "delete",
        "delete_child",
        "write",
        "write_data",
        "append_data",
        "rename",
        "set_ea",
        "generic_write",
        "create"
    ]

    # Scan fields individually (same logic, less overhead)
    for kw in destructive_keywords:
        if kw in access_raw or kw in access_mask or kw in access_reason:
            return True

    # Hex fallback unchanged
    if access_mask and "0x" in access_mask:
        return False

    return False



def algorithm(event):
    acct = event.get("source_account_name")
    if not acct or acct in ["-", "UNKNOWN", None]:
        return 0.0

    # EARLY EXIT improves performance
    evt_id = str(event.get("event_id", ""))
    if evt_id not in ("4663", "5145"):
        return 0.0

    if _is_whitelisted_account(acct):
        return 0.0

    if not _is_destructive_action(event):
        return 0.0

    stat_key = "massfiledeletionandencription"
    stats.count(stat_key)

    if stats.getcount(stat_key) > 100:
        return 1.0

    return 0.0



# def _is_whitelisted_account(account):
#     if not account:
#         return False
#     an = account.strip().lower()
#     for w in WHITELIST_ACCOUNTS:
#         if w.lower() in an:
#             return True
#     return False

# def _is_destructive_action(event):

#     # EventID check
#     evt = str(event.get("event_id", ""))
#     if evt not in ("4663", "5145"):
#         # still allow other file-like events if they have access info, but prefer these IDs
#         pass

#     # Check various fields for destructive verbs
#     access_raw = (event.get("access_list_raw") or "") or ""
#     access_mask = (event.get("access_mask_hex") or "") or ""
#     access_reason = (event.get("access_reason_detail") or "") or ""
#     # combine lowercase strings for keyword search
#     combined = " ".join([str(access_raw), str(access_mask), str(access_reason)]).lower()

#     destructive_keywords = [
#         "delete",           # obvious
#         "delete_child",     # directory child deletion
#         "write",            # write / overwrite
#         "write_data",       # NTFS verb for write
#         "append_data",
#         "rename",           # rename may be used during mass renames for encryption
#         "set_ea",           # sometimes used by ransomware (extended attributes)
#         "generic_write",
#         "create"            # creation of encrypted files could follow deletion of originals
#     ]

#     for kw in destructive_keywords:
#         if kw in combined:
#             return True

#     # As a fallback, examine the access_mask_hex value pattern that often indicates deletions or writes.
#     # Many environments store hex like '0x10000' etc. We treat presence of hex as ambiguous; rely on keywords mainly.
#     if access_mask and "0x" in str(access_mask).lower():
#         # don't assume destructive, return False unless keywords matched above
#         return False

#     return False

# def algorithm(event):
#     acct = event.get("source_account_name")
#     if not acct or acct in ["-", "UNKNOWN", None]:
#         return 0.0

#     # Ignore whitelisted automation/backup/system accounts
#     if _is_whitelisted_account(acct):
#         return 0.0

#     # Heuristic: only consider file access events
#     evt_id = str(event.get("event_id", ""))
#     if evt_id not in ("4663", "5145"):
#         # Still try to detect based on content, but prioritize known file audit IDs
#         return 0.0

#     # Check if this specific event looks destructive
#     if not _is_destructive_action(event):
#         return 0.0

#     # Build per-group stat key so counts are scoped to host+user
#     stat_key = "massfiledeletionandencription"

#     stats.count(stat_key)
  
#     if stats.getcount(stat_key) > 100:
#       return 1.0

#     return 0.0

def context(event_data):
    acct = event_data.get("source_account_name")
    host = event_data.get("host")
    share = event_data.get("share_name") or event_data.get("share_path") or "-"
    sample_file = event_data.get("target_relative_path") or "-"
    count = stats.getcount("massfiledeletionandencription") 

    return (
        "User '%s' performed numerous destructive file operations on file server '%s' (share='%s', example='%s'). "
        "Destructive ops in window: %s. This may indicate ransomware activity (mass deletion/encryption)."
    ) % (acct, host, share, sample_file, str(count))

def criticality():
    return "CRITICAL"

def tactic():
    return "Impact (TA0040)"

def technique():
    return "Data Encrypted for Impact (T1486)"

def artifacts():
    # Useful fields to attach to the alert
    return stats.collect([
        "event_id",
        "host",
        "source_ip",
        "source_port",
        "source_account_name",
         "share_name",
        "share_path",
        "target_relative_path",
        "access_list_raw",
        "access_mask_hex",
        "source_process_name",
    ])



def entity(event):
    actor = event.get('source_account_name')
       
    return {"derived": False, "value": actor, "type": "accountname"}


