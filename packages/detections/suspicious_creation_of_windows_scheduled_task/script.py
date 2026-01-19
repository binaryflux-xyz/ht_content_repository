def window():
    # Check for scheduled task creation events within 15 minutes
    return '15m'
  
def groupby():
    # Group by source account and host (user creating the task)
    return ['source_account_name', 'host']

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
  
def algorithm(event):
    evt_id = str(event.get("event_id"))
    if evt_id != "4698":
        return 0.0
    creator = event.get("source_account_name")
    task_name = event.get("task_name") or event.get("target_relative_path")
    host = event.get("host")
    command = event.get("process_name") or event.get("command") or "-"
    src_ip = event.get("source_ip")
    # Ignore system-created tasks (noise reduction)
    if task_name and any(x in task_name.lower() for x in [
        "\\microsoft\\windows\\defrag", 
        "\\microsoft\\windows\\servicing", 
        "\\microsoft\\windows\\update"
    ]):
        return 0.0

    # Ignore creation by SYSTEM or TrustedInstaller
    if creator and creator.lower() in ["system", "trustedinstaller", "networkservice", "localservice"]:
        return 0.0

    # High confidence if non-admin user creates a scheduled task
    return 0.75
    
def context(event_data):
    acct = event_data.get("source_account_name")
    host = event_data.get("host")
    task_name = event_data.get("target_relative_path")
    proc = event_data.get("process_name")
    return (
        "A new Windows Scheduled Task '%s' was created on host '%s' by account '%s'. "
        "Command: '%s'. This may indicate persistence or automated malicious activity."
    ) % (task or "-", host, acct or "-", cmd)
def criticality():
    return 'HIGH'
def tactic():
    return 'Persistence (TA0003)'
def technique():
    return 'Scheduled Task/Job (T1053/005)'
def artifacts():
    return stats.collect(["event_id",
        "host",
        "source_account_name",
        "source_account_domain",
        "source_ip",
        "target_relative_path",   # the scheduled task name/path
        "process_name",          ])

def entity(event):
    task = event.get("target_relative_path")
    return {'derived': False, 'value': task, 'type': 'task'}