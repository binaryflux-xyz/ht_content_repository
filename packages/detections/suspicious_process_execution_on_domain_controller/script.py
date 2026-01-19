# Detection: Suspicious Process Creation on Domain Controller
# Purpose: Detect non-standard or suspicious process execution on Domain Controllers (PowerShell, cmd, rundll32, etc.)
# Events: Sysmon 1 (ProcessCreate), 7 (ImageLoad), 10 (ProcessAccess)
# Condition: Execution of suspicious process names or command-line tools on hosts identified as DCs
# MITRE: Command and Scripting Interpreter: PowerShell (T1059.001) / Execution (TA0002)

def window():
    return '2m'  # short window — single event usually enough

def groupby():
    return ['host']
def investigate():
    return "windows_server_session_analyser"

def automate():
    return False
def algorithm(event):
    evt_id = int(event.get('event_id') or 0)
    if evt_id not in [1, 7, 10]:
        return 0.0

    host = event.get('host').upper()
    process_name = event.get('process_name').lower()
    command_line = event.get('command_line').lower()

    # Only apply to domain controllers (basic heuristic: name contains DC)
    if "DC" not in host and "DOMAIN" not in host:
        return 0.0

    # Suspicious process list (expandable)
    suspicious_processes = [
        'powershell.exe',
        'cmd.exe',
        'rundll32.exe',
        'wmic.exe',
        'wscript.exe',
        'cscript.exe',
        'mshta.exe',
        'regsvr32.exe',
        'psexec.exe'
    ]

    # Check process name or command line content
    for s in suspicious_processes:
        if s in process_name or s in command_line:
            return 1.0

    return 0.0

def context(event_data):
    host = event_data.get('host')
    proc = event_data.get('process_name')
    cmd = event_data.get('command_line')
    return "Suspicious process '%s' executed on Domain Controller %s with command line: %s." % (proc, host, cmd)

def criticality():
    return "CRITICAL"

def tactic():
    return "Execution (TA0002)"

def technique():
    return "Command and Scripting Interpreter (T1059/001)"

def artifacts():
    return stats.collect([
     
        "event_id",
        "host",
     
        "process_name",
 
        "command_line",
      
        "source_account_name",
        "source_ip"
    ])

def entity(event):
    host = event.get('host')
    return {"derived": False, "value": host, "type": "hostname"}
