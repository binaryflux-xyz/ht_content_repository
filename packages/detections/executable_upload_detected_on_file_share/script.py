

def window():
    # short window; single event is usually enough
    return '1m'

def groupby():
    # group by host and actor to scope events
    return ['host', 'source_account_name', 'file_path']
def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
def algorithm(event):
    # normalize event id (no try/except per preference)
    evt_id = event.get('event_id') 

    # relevant fields
    file_path = (event.get('file_path') or event.get('object_name') or event.get('target_filename') or "").lower()
    host = event.get('host') 
    user = event.get('source_account_name') 

    # Quick checks: must have a file path and .exe extension
    if not file_path or not file_path.endswith('.exe'):
        return 0.0

    # Ensure path looks like a share (UNC path or contains backslash)
    if not ('\\\\' in file_path or '/' in file_path or '\\' in file_path):
        # not clearly a file path on a share/host
        return 0.0

    # For 4663 ensure access indicates write/create
    if evt_id == 4663:
        access_info = (event.get('access_mask') or event.get('accesses') or event.get('permissions') or event.get('operation') or "").upper()
        if not ('WRITE' in access_info or 'CREATE' in access_info or 'WRITE_DATA' in access_info or 'ADD' in access_info):
            return 0.0
        return 0.95

    # Sysmon FileCreate event (commonly event_id 11)
    if evt_id == 11:
        # Sysmon usually logs creation/write; treat as match
        return 0.95

    # Some pipelines use Sysmon event id as 11 under source 'sysmon' or 'Sysmon'
    source = (event.get('source') or event.get('provider') or "").lower()
    if evt_id == 0 and 'sysmon' in source and 'filecreate' in (event.get('event_name') or "").lower():
        return 0.95

    return 0.0

def context(event_data):
    file_path = (event_data.get('file_path') or event_data.get('object_name') or event_data.get('target_filename') or "<unknown-file>")
    host = event.get('host') 
    user = event.get('source_account_name') 

    return "Executable file %s was written to a share on host %s by user %s." % (file_path, host, user)

def criticality():
    return "HIGH"

def tactic():
    return "Command and Control (TA0011)"

def technique():
    return "Ingress Tool Transfer (T1105)"

def artifacts():
    return stats.collect([
        "event_id",
        "host",
      
        "source_account_name",
        "file_path",
        "process_name",
    ])

def entity(event):
    actor = event.get('source_account_name')
    return {"derived": False, "value": actor, "type": "accountname"}
