def steps():
    return [
        {
            "name": "action",
            "parameters": {
                "action": "EventSession",
                "fields": {
                    "event->>'provider'": {
                        "step": 0,
                        "path": "streamprovider"
                    }
                }
            },
            "template":"The log details a series of auditing events related to Windows Security Audit logging, with the common account appearing across multiple entries indicating potential user-specific security audits. The timestamps reveal these actions occurred in quick succession, suggesting a short window of activity or batch processing involving a specific session or user interaction within Windows systems monitoring capabilities."
        }, #1
        {
            "name": "execute_python",
            "parameters": {
                "code": """
from typing import List, Dict, Any
import json

def _normalize_event(e: Dict[str, Any]) -> Dict[str, Any]:
    '''Bring common fields to predictable names for matching.'''
    out = dict(e)
    
    for key in ('TargetLogonId', 'LogonId', 'LogonID', 'SubjectLogonId'):
        if key in e:
            out['logon_id'] = str(e[key]).lower()
            break

    for key in ('LogonGuid', 'logonGuid', 'LogonGUID'):
        if key in e:
            out['logon_guid'] = str(e[key]).lower()
            break
    
    for key in ('TargetUserName', 'AccountName', 'UserName', 'User'):
        if key in e:
            out['user'] = e[key]
            break
    
    for key in ('IpAddress', 'Ip', 'IpAddr', 'SourceNetworkAddress', 'IpAddressRaw'):
        if key in e:
            out['src_ip'] = e[key]
            break
    
    # process + cmdline normalization
    for key in ('NewProcessName', 'Image', 'ProcessName', 'CommandLine'):
        if key in e and 'process' not in out:
            if 'NewProcessName' in e or 'Image' in e or 'ProcessName' in e:
                out['process'] = e.get('NewProcessName') or e.get('Image') or e.get('ProcessName')
            if 'CommandLine' in e:
                out['cmdline'] = e.get('CommandLine')
    
    # file access
    for key in ('ObjectName', 'TargetObject', 'FileName'):
        if key in e:
            out['path'] = e[key]
            break

    # network
    for key in ('DestinationIp', 'DestinationIpAddress', 'DestIp', 'NetworkAddress', 'RemoteIp'):
        if key in e:
            out['dest_ip'] = e[key]
            break

    for key in ('DestinationPort', 'DestPort', 'RemotePort'):
        if key in e:
            try:
                out['dest_port'] = int(e[key])
            except Exception:
                out['dest_port'] = None
            break
    
    # event id extraction
    if 'EventID' in e:
        out['event_id'] = int(e['EventID'])
    elif 'event_id' in e:
        out['event_id'] = int(e['event_id'])
    else:
        out['event_id'] = None

    for key in ("EnabledPrivilegeList", "PrivilegeList", "DisabledPrivilegeList", "DisabledPrivileges"):
        if key in e:
            out[key] = e[key]

    return out


def _unwrap_windows_event(container: Dict[str, Any]) -> Dict[str, Any]:
    msg = container.get('message')
    if msg is None:
        return {}

    # Parse the JSON string inside "message"
    try:
        outer = json.loads(msg) if isinstance(msg, str) else msg
    except Exception:
        return {}

    # CASE 1: Your logs are already flat JSON with real event fields
    if isinstance(outer, dict) and (
        "EventID" in outer or 
        "event_id" in outer or 
        "EventTime" in outer
    ):
        return outer

    # CASE 2: Sysmon-style nested "log"
    if isinstance(outer, dict) and "log" in outer:
        log = outer["log"]
        if isinstance(log, str):
            try:
                return json.loads(log)
            except:
                return log
        if isinstance(log, dict):
            return log

    # CASE 3: Fallback
    if isinstance(outer, dict):
        return outer

    return {}


def process_events(raw_events: List[Dict[str, Any]]) -> Dict[str, Any]:

    preprocessed: List[Dict[str, Any]] = []

    for e in raw_events:
        if isinstance(e, dict):

            # only keep Microsoft events
            if e.get("provider") != "Microsoft":
                continue

            # already unwrapped event
            if 'EventID' in e or 'event_id' in e:
                preprocessed.append(e)

            # flatten "message" JSON
            elif 'message' in e:
                inner = _unwrap_windows_event(e)
                preprocessed.append(inner or e)

            else:
                preprocessed.append(e)

    events = [_normalize_event(e) for e in preprocessed]

    logons = []
    privs = []
    processes = []
    fileaccess = []
    network = []
    usb_hits = []

    for ev in events:
        eid = ev.get('event_id')

        if eid in (4624, 4625):
            logons.append(ev)
        elif any(
            key in ev
            for key in (
                "EnabledPrivilegeList",
                "PrivilegeList",
                "DisabledPrivilegeList",
                "DisabledPrivileges"
                )):
                    privs.append(ev)
        elif eid in (4688, 1):
            processes.append(ev)
        elif eid in (4663, 11):
            fileaccess.append(ev)
        elif eid in (5156, 5158, 3):
            network.append(ev)
        elif eid == 6 or (ev.get('EventID') in (4663,) and ev.get('path')):
            usb_hits.append(ev)

    return {
        'events': events,
        'logons': logons,
        'privileges': privs,
        'processes': processes,
        'fileaccess': fileaccess,
        'network': network,
        'usb_hits': usb_hits
    }

output = process_events(session)
""",
                "variables": {
                    "session":"step.1.output.result"
                }
            },
            "template":"""
{%- set total_events = output | length -%}
{%- set with_event_id = output | selectattr('event_id') | list -%}
{%- set with_user = output | selectattr('user') | list -%}
{%- set with_process = output | selectattr('process') | list -%}
{%- set with_network = output | selectattr('dest_ip') | list -%}
{%- set normalized = (with_event_id | length + with_user | length + with_process | length + with_network | length) / 4 -%}

{%- if not output or total_events == 0 -%}
No valid Windows event data was processed. The input dataset appears empty or did not contain any recognizable event structures for normalization.
{%- else -%}
The preprocessing pipeline successfully parsed and normalized {{ total_events }} raw Windows event{{ 's' if total_events > 1 else '' }}. Each record was examined to extract consistent field names such as event ID, logon ID, user account, source IP, destination details, and process paths. 
{%- if with_event_id | length < total_events -%}
Some entries lacked explicit event identifiers and were retained in their raw form to preserve data completeness. 
{%- endif -%}
{%- if with_user | length > 0 -%}
User information was successfully extracted from {{ with_user | length }} event{{ 's' if with_user|length > 1 else '' }}, improving traceability across authentication, process, and network logs. 
{%- endif -%}
{%- if with_process | length > 0 -%}
Process-related attributes were normalized in {{ with_process | length }} case{{ 's' if with_process|length > 1 else '' }}, ensuring reliable correlation with file access and execution activities. 
{%- endif -%}
{%- if with_network | length > 0 -%}
Network destination fields were standardized for {{ with_network | length }} event{{ 's' if with_network|length > 1 else '' }}, facilitating downstream detection of exfiltration or remote access behaviors. 
{%- endif -%}
Overall, the dataset is now structured uniformly, enabling efficient correlation, enrichment, and anomaly detection in subsequent analysis stages.
{%- endif -%}
"""
        }, #2
        {
            "name": "execute_python",
            "parameters": {
                "code": """
from typing import List, Dict, Any

def analyze_auth(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    '''Extract logon events (4624/4625) and basic auth context.'''
    results: Dict[str, Any] = {}
    logons = [ev for ev in events if ev.get('event_id') in (4624, 4625)]
    results['logons'] = logons
    for ev in logons:
        user = ev.get('user', ev.get('TargetUserName'))
        lt = ev.get('LogonType') or ev.get('LogonTypeName') or ev.get('Logon_Type')
        results.setdefault('auth_summary', []).append({
            'event_id': ev.get('event_id'),
            'user': user,
            'logon_type': lt,
            'src_ip': ev.get('src_ip'),
            'time': ev.get('EventTime') or ev.get('TimeCreated') or ev.get('EventReceivedTime')
        })
    return results

output = analyze_auth(session)
""",
                "variables": {
                    "session":"step.2.output.logons"
                }
            },
            "template":"""\
{%- set auth_summary = output.auth_summary or [] -%}

{%- if not auth_summary -%}
The provided audit logs do not contain any information related to successful logon events. All observed activity pertains to general system operations, such as handle manipulations and file access, without evidence of any new user authentication attempts. This indicates that no account logons occurred during the analyzed timeframe.
{%- else -%}
{%- set total_logons = auth_summary | length -%}
{%- set users = auth_summary | map(attribute='user') | select | unique | list -%}
{%- set unique_ips = auth_summary | map(attribute='src_ip') | select | unique | list -%}
{%- set successful = auth_summary | selectattr("event_id", "equalto", 4624) | list -%}
{%- set failed = auth_summary | selectattr("event_id", "equalto", 4625) | list -%}
{%- set main_user = users[0] if users else "an unidentified account" -%}


{%- if successful | length == 0 -%}
The analyzed authentication logs show only failed logon attempts associated with {{ main_user }}. Each event indicates that the authentication request was rejected, suggesting possible incorrect credentials or intentional probing. The absence of successful logons implies that unauthorized access was effectively prevented during this period.
{%- elif failed | length == 0 -%}
Multiple successful logon events were observed for the account {{ main_user }} within the analyzed period. Each entry records relevant parameters such as logon type, timestamps, and originating IP addresses ({{ unique_ips | join(', ') if unique_ips else 'N/A' }}). All are marked as Audit Success, reflecting routine authentication activity with no signs of anomalies or privilege misuse.
{%- else -%}
The authentication data reveals both successful and failed logon attempts for {{ main_user }} during the observed window. Of the {{ total_logons }} recorded events, {{ successful | length }} were successful while {{ failed | length }} failed. The activity originated from {{ unique_ips | length }} distinct IP addresses ({{ unique_ips[:3] | join(', ') }}{% if unique_ips | length > 3 %}...{% endif %}), indicating regular use patterns interspersed with occasional authentication errors. Although the mix appears typical, repeated failures should be reviewed to rule out credential misuse or brute-force attempts.
{%- endif -%}
{%- endif -%}
""",
          "artifacts":["recurring","limited"]
        }, #3
        {
            "name": "execute_python",
            "parameters": {
                "code": """
from typing import List, Dict, Any

HIGH_PRIVILEGES = [
    'SeDebugPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege',
    'SeTakeOwnershipPrivilege', 'SeImpersonatePrivilege', 'SeEnableDelegationPrivilege'
]

def analyze_privileges(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    '''Detect privilege grants found anywhere, not only in 4672 events.'''
    results: Dict[str, Any] = {}
    privs = []

    for ev in events:
        # NEW condition: look for privileges in ANY event
        plist = (
            ev.get('EnabledPrivilegeList') or
            ev.get('PrivilegeList') or
            ev.get('privileges') or
            ''
        )

        if not plist:
            continue

        # SAME LOGIC: detect only HIGH_PRIVILEGES
        detected = [p for p in HIGH_PRIVILEGES if p.lower() in plist.lower()]

        if detected:
            privs.append({'event': ev, 'detected': detected})

    results['privileges'] = privs

    if privs:
        unique = list(set(p for d in privs for p in d['detected']))
        results.setdefault('notes', []).append(
            "High privileges detected: " + ", ".join(unique)
        )


    return results

output = analyze_privileges(session)
""",
                "variables": {
                    "session":"step.2.output.privileges"
                }
            },
            "template":"""\
{%- set privs = output.privileges or [] -%}
{%- set detected = [] -%}

{# Collect detected privilege names #}
{%- for p in privs -%}
  {%- set d = p.detected -%}
  {%- if d is string and d -%}
    {%- set _ = detected.append(d) -%}
  {%- elif d is iterable -%}
    {%- for x in d -%}
      {%- if x -%}
        {%- set _ = detected.append(x|string) -%}
      {%- endif -%}
    {%- endfor -%}
  {%- endif -%}
{%- endfor -%}

{%- set uniq_privs = detected | unique | sort -%}

{%- if uniq_privs -%}
  {%- set priv_list = uniq_privs | join(', ') -%}
  The security report identifies a high level of privileges being assigned to the newly created account,
  specifically {{ priv_list }}. This suggests that the user might be configured for elevated system operations
  which could pose a significant security risk if not properly controlled. The audit log entry under Special
  Logon category further confirms these privileges being granted to the new account upon login. It is recommended
  to review the role assignments and permissions of this newly created user account, especially in environments
  where high-level administrative rights are required, to ensure they align with intended security policies.
{%- else -%}
The provided audit logs do not contain any information pertaining to privileges such as permission changes, access control lists (ACLs), elevation events, or similar security-related actions.
{%- endif -%}
            """,
            "artifacts":["administrative misuse"]
        }, #4
        {
            "name": "execute_python",
            "parameters": {
                "code": """
from typing import List, Dict, Any
import re

SUSPICIOUS_PROCS = [
    'powershell.exe', 'pwsh.exe', 'cmd.exe', 'rundll32.exe',
    'wmic.exe', 'psexec.exe', 'mimikatz.exe', 'rclone.exe', 'certutil.exe'
]

ARCHIVE_COMMANDS = ['7z', '7za', 'zip', 'rar', 'tar', 'compress', 'winrar', 'gzip']

def analyze_processes(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    '''Find suspicious processes and archive/staging commands.'''
    results: Dict[str, Any] = {}
    suspicious = []
    staging = []
    for ev in events:
        if ev.get('event_id') in (4688, 1): 
            proc = (ev.get('process') or '').lower()
            cmd = (ev.get('cmdline') or ev.get('CommandLine') or '').lower()
            if not proc and cmd:
                
                m = re.match(r'^\\s*\\'?([^\\'\\s]+)\\'?', cmd)
                if m:
                    proc = m.group(1).lower()
            if proc:
                for s in SUSPICIOUS_PROCS:
                    if s in proc:
                        suspicious.append({'event': ev, 'proc': proc, 'cmd': cmd})
                        break
                
                if any(a in cmd or a in proc for a in ARCHIVE_COMMANDS):
                    staging.append({'event': ev, 'proc': proc, 'cmd': cmd})
    results['suspicious_processes'] = suspicious
    results['staging_processes'] = staging
    if suspicious:
        unique_procs = list(set(s['proc'] for s in suspicious))
        results.setdefault('notes', []).append(
            "Suspicious processes seen: " + ", ".join(unique_procs)
        )
    if staging:
        results.setdefault('notes', []).append("Staging/archive commands seen: " + str(len(staging)))
    return results

output = analyze_processes(session)
""",
                "variables": {
                    "session":"step.2.output.processes"
                }
            },
            "template":"""
{%- set suspicious = output.suspicious_processes or [] -%}
{%- set staging = output.staging_processes or [] -%}

{%- if not suspicious and not staging -%}
The analysis of process creation events did not reveal any suspicious or unusual activity. All observed processes appear consistent with normal system or user behavior, with no indicators of potential misuse or data staging.
{%- else -%}
{%- if suspicious -%}
Analysis of the Windows process creation logs revealed the execution of potentially high-risk processes such as {{ suspicious | map(attribute='proc') | unique | sort | join(', ') }}. These utilities are frequently leveraged by threat actors for command execution, system reconnaissance, privilege escalation, or credential theft. Their presence may indicate post-exploitation activity or unauthorized administrative access.
{%- endif -%}
{%- if staging -%}
Additionally, {{ staging | length }} process event(s) involved the use of archiving or compression tools (e.g., {{ staging | map(attribute='proc') | unique | sort | join(', ') }}). Such activity can signify data staging, exfiltration preparation, or attempts to conceal data movement within the system.
{%- endif -%}
Further review of related file access, network activity, and authentication logs is recommended to determine whether this behavior aligns with legitimate administrative tasks or indicates compromise.
{%- endif -%}
""",
          "artifacts":["{{ (output.suspicious_processes or []) | length }} process{{ 'es' if ((output.suspicious_processes or []) | length) != 1 else '' }}", "{{ (output.staging_processes or []) | length }} process{{ 'es' if ((output.staging_processes or []) | length) != 1 else '' }}"]
        }, #5
        {
            "name": "execute_python",
            "parameters": {
                "code": """
from typing import List, Dict, Any

SENSITIVE_PATHS = [
    r'C:\\Windows\\NTDS',
    r'C:\\Windows\\System32\\config',
    r'C:\\ProgramData\\Microsoft\\Crypto',
    r'C:\\inetpub\\wwwroot',
    r'C:\\Users\\Administrator',
    r'C:\\Users\\Public',
    r'C:\\Temp',
    r'D:\\Backups',
    r'E:\\Data',
    r'C:\\Windows\\SYSVOL',
    r'C:\\Shares\\\\', r'D:\\Shares\\\\'
]

CRITICAL_PATH_KEYWORDS = [
    'ntds.dit',
    r'\\system32\\config\\sam',
    r'\\system32\\config\\security',
    r'\\system32\\config\\system'
]

def _path_matches_sensitive(path: str) -> bool:
    if not path:
        return False
    p = path.replace('/', '\\\\').lower()
    for sp in SENSITIVE_PATHS:
        if sp.replace('\\\\', '\\\\').lower() in p:
            return True
    for key in CRITICAL_PATH_KEYWORDS:
        if key.lower() in p:
            return True
    return False

def analyze_file_access(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    '''Find file access events touching sensitive paths.'''
    results: Dict[str, Any] = {}
    matches = []
    for ev in events:
        if ev.get('event_id') in (4663, 11):
            path = ev.get('path') or ev.get('ObjectName') or ev.get('TargetObject')
            if path and _path_matches_sensitive(path):
                critical_hit = any(k.lower() in path.lower() for k in CRITICAL_PATH_KEYWORDS)
                matches.append({'event': ev, 'path': path, 'critical': critical_hit})
    results['file_access_matches'] = matches
    if matches:
        crit = [m for m in matches if m['critical']]
        results.setdefault('notes', []).append("Sensitive file access count: " + str(len(matches)) + "; critical hits: " + str(len(crit)))
    return results

output = analyze_file_access(session)
""",
                "variables": {
                    "session":"step.2.output.fileaccess"
                }
            },
            "template":"""
{%- set matches = output.file_access_matches or [] -%}
{%- set critical = matches | selectattr('critical') | list -%}

{%- if not matches -%}
No evidence of access to sensitive or high-value system paths was identified in the analyzed file access events. All recorded file operations appear routine and consistent with normal user or application behavior, with no indicators of credential harvesting or configuration tampering.
{%- else -%}
Analysis of Windows file access logs detected {{ matches | length }} event{{ 's' if matches|length > 1 else '' }} involving access to sensitive or protected directories. These locations often contain system configuration data, user credentials, or administrative files that are not typically accessed during standard operations.
{%- if critical -%}
Notably, {{ critical | length }} event{{ 's' if critical|length > 1 else '' }} targeted critical system files such as the Windows SAM, SECURITY, or SYSTEM registry hives. These files are essential to authentication and security mechanisms, and unauthorized access may indicate credential dumping, privilege escalation attempts, or system reconnaissance by a malicious actor.
{%- endif -%}
Such activity warrants close investigation to confirm whether it originated from legitimate administrative processes, automated system maintenance, or potentially malicious behavior. Correlating these findings with process creation and authentication logs is recommended to assess the broader context and potential intent.
{%- endif -%}
""",
          "artifacts":["{{ (output.file_access_matches or []) | length }} event{{ 's' if ((output.file_access_matches or []) | length) != 1 else '' }}"]
        }, #6
        {
            "name": "execute_python",
            "parameters": {
                "code": """
from typing import List, Dict, Any

EXFIL_PORTS = {21, 22, 80, 443, 445, 8080} 

CLOUD_TARGET_KEYWORDS = ['drive.google', 'dropbox', 'onedrive', 'amazonaws', 's3.amazonaws', 'box.com', 'cloudflare']


def _ci_contains_any(text: str, patterns: List[str]) -> bool:
    if not text:
        return False
    low = text.lower()
    for p in patterns:
        if p.lower() in low:
            return True
    return False

def analyze_network(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    '''Check outbound connections for suspicious apps/ports/cloud targets.'''
    results: Dict[str, Any] = {}
    net_matches = []
    for ev in events:
        if ev.get('event_id') in (5156, 5158, 3):
            app = (ev.get('ApplicationName') or ev.get('app') or ev.get('process') or '').lower()
            dest = (ev.get('dest_ip') or ev.get('DestinationIp') or ev.get('DestinationAddress') or '')
            port = ev.get('dest_port') or ev.get('DestinationPort') or 0
            try:
                port = int(port)
            except Exception:
                port = 0
            reason = []
            if port in EXFIL_PORTS:
                reason.append('exfil-port')
            if _ci_contains_any(dest, CLOUD_TARGET_KEYWORDS) or _ci_contains_any(app, CLOUD_TARGET_KEYWORDS):
                reason.append('cloud-target')
            if 'powershell' in app or 'rclone' in app or 'curl' in app or 'wget' in app:
                reason.append('suspicious-app')
            if reason:
                net_matches.append({'event': ev, 'app': app, 'dest': dest, 'port': port, 'reasons': reason})
    results['network_matches'] = net_matches
    if net_matches:
        results.setdefault('notes', []).append("Network exfil indicators: " + str(len(net_matches)))
    return results


output = analyze_network(session)
""",
                "variables": {
                    "session":"step.2.output.network"
                }
            },
            "template":"""
{%- set matches = output.network_matches or [] -%}

{%- if not matches -%}
No suspicious outbound network activity was identified in the analyzed events. All recorded connections appear consistent with normal application behavior and legitimate network communication, with no signs of data exfiltration or unauthorized external access.
{%- else -%}
Analysis of Windows network connection events revealed {{ matches | length }} connection{{ 's' if matches|length > 1 else '' }} that may indicate potential data exfiltration or unauthorized outbound communication.
{%- set exfil = matches | selectattr('reasons', 'contains', 'exfil-port') | list -%}
{%- set cloud = matches | selectattr('reasons', 'contains', 'cloud-target') | list -%}
{%- set suspicious_apps = matches | selectattr('reasons', 'contains', 'suspicious-app') | list -%}
{%- if exfil -%}
A number of connections were established over commonly abused data-transfer ports such as 21, 22, 80, 443, 445, or 8080. These channels are frequently leveraged by attackers to blend exfiltration traffic with legitimate web or file-transfer activity.
{%- endif -%}
{%- if cloud -%}
Several connections targeted external cloud services such as Google Drive, Dropbox, OneDrive, AWS S3, or Box. Outbound communication to these domains can suggest potential data staging or transfer to third-party cloud storage.
{%- endif -%}
{%- if suspicious_apps -%}
Processes such as {{ suspicious_apps | map(attribute='app') | unique | sort | join(', ') }} were observed initiating network connections. These utilities are often used for command execution or scripted data transfers (e.g., PowerShell, curl, rclone, wget) and may indicate automated exfiltration or command-and-control behavior.
{%- endif -%}
Correlating these findings with file access and process creation logs is recommended to determine whether the observed network activity aligns with authorized administrative operations or reflects malicious intent.
{%- endif -%}
""",
          "artifacts":["{{ (output.network_matches or []) | length }} connection{{ 's' if ((output.network_matches or []) | length) != 1 else '' }}"]
        }, #7
        {
            "name": "execute_python",
            "parameters": {
                "code": """
from typing import List, Dict, Any

def analyze_usb(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    '''Detect removable media mounts or file copies to removable devices.'''
    results: Dict[str, Any] = {}
    usb_hits = []
    for ev in events:
        
        if ev.get('event_id') in (6,):
            usb_hits.append(ev)
        
        if ev.get('EventID') in (4663,) and ev.get('path'):
            
            if re.match(r'^[A-Z]:\\\\\\\\', ev.get('path') or '') and (ev.get('path', '').upper().startswith(('E:\\\\', 'F:\\\\', 'G:\\\\', 'H:\\\\'))):
                usb_hits.append(ev)
    results['usb_hits'] = usb_hits
    if usb_hits:
        results.setdefault('notes', []).append("Removable media activity: " + str(len(usb_hits)))

    return results

output = analyze_usb(session)
""",
                "variables": {
                    "session":"step.2.output.usb_hits"
                }
            },
            "template":"""
{%- set usb_hits = output.usb_hits or [] -%}

{%- if not usb_hits -%}
No removable media activity was detected in the analyzed Windows event logs. There were no indications of USB devices being connected, mounted, or accessed during the observation period.
{%- else -%}
Analysis of the event logs identified {{ usb_hits | length }} instance{{ 's' if usb_hits|length > 1 else '' }} of removable media activity. This includes detection of USB device connections or file operations directed toward external drives such as E:, F:, G:, or H:. Such behavior can indicate data transfer to portable storage devices, which may represent legitimate administrative actions or potential data exfiltration attempts depending on the context. It is recommended to review associated file access logs, process activity, and user sessions to determine whether these operations were authorized. Correlation with network or process creation events may also help validate whether this behavior aligns with standard operational practices or reflects policy violations.
{%- endif -%}
""",
          "artifacts":["{{ (output.usb_hits or []) | length }} removable media connection{{ 's' if ((output.usb_hits or []) | length) != 1 else '' }}"]
        }, #8
        {
            "name": "execute_python",
            "parameters": {
                "code": """
from typing import Dict

def assign_verdict(file_access_matches: Dict, network_matches: Dict, privileges: Dict, processes: Dict, usb_hits: Dict, auth_summary: Dict) -> Dict:
    results: Dict[str, Any] = {}

    account_name = ""
    account_sid = ""

    # 1) Try getting user from authentication summary
    if auth_summary.get("auth_summary"):
        first = auth_summary["auth_summary"][0]
        account_name = str(first.get("user", "")).lower()

    # 2) Fallback: privilege events
    if not account_name and privileges.get("privileges"):
        ev = privileges["privileges"][0]["event"]
        account_name = str(ev.get("SubjectUserName", "")).lower()
        account_sid = str(ev.get("SubjectUserSid", "")).lower()

    # 3) Fallback: suspicious processes
    if not account_name and processes.get("suspicious_processes"):
        ev = processes["suspicious_processes"][0]["event"]
        account_name = str(ev.get("SubjectUserName", "")).lower()
        account_sid = str(ev.get("SubjectUserSid", "")).lower()

    # 4) Fallback: file access
    if not account_name and file_access_matches.get("file_access_matches"):
        ev = file_access_matches["file_access_matches"][0]["event"]
        account_name = str(ev.get("SubjectUserName", "")).lower()
        account_sid = str(ev.get("SubjectUserSid", "")).lower()

    is_machine = account_name.endswith("$")
    is_service = account_name.startswith(("svc_", "service_", "app_", "batch_"))
    is_local_admin = account_sid.endswith("-500")
    is_domain_admin = account_sid.endswith("-512")
    is_system = (account_sid == "s-1-5-18")

    if is_machine or is_service or is_local_admin or is_domain_admin or is_system:
        return {
            "verdict": "BENIGN",
            "reasons": ["Suspicious activity observed but suppressed because this is a privileged account (admin/service/system)."],
            "auth_summary": auth_summary.get("auth_summary", []),
            "privileges": privileges.get("privileges", []),
            "suspicious_processes": processes.get("suspicious_processes", []),
            "staging_processes": processes.get("staging_processes", []),
            "file_access_matches": file_access_matches.get("file_access_matches", []),
            "network_matches": network_matches.get("network_matches", []),
            "usb_hits_count": len(usb_hits.get("usb_hits", [])),
            "notes": ["Privileged account detected — verdict forced to BENIGN."]
        }


    all_dicts = (
        file_access_matches,
        network_matches,
        privileges,
        processes,
        usb_hits,
        auth_summary,
    )

    # Flatten all 'notes' lists from input dicts
    combined_notes = []
    for d in all_dicts:
        notes = d.get("notes", [])
        for note in notes:
            if note:  # ignore None or empty strings
                combined_notes.append(note)
    
    results['notes'] = combined_notes


    reasons = []
    verdict = 'BENIGN'
    file_matches = file_access_matches.get('file_access_matches', [])
    net_matches = network_matches.get('network_matches', [])
    privs = privileges.get('privileges', [])
    suspicious_procs = processes.get('suspicious_processes', [])
    staging = processes.get('staging_processes', [])
    usb = usb_hits.get('usb_hits', [])

    
    if any(m.get('critical') for m in file_matches):
        reasons.append('Critical sensitive artifact accessed (NTDS/Registry hives).')
        verdict = 'CRITICAL'

    
    if file_matches and net_matches:
        reasons.append('Sensitive files accessed and network exfil indicators present.')
        verdict = 'CRITICAL'

    
    if file_matches and usb:
        reasons.append('Sensitive files accessed and removable media activity detected.')
        verdict = 'CRITICAL'

    
    if privs:
        reasons.append('High privileges granted during session.')
        if suspicious_procs or staging:
            reasons.append('High privileges combined with suspicious process execution.')
            verdict = 'SUSPICIOUS' if verdict != 'CRITICAL' else verdict

    if suspicious_procs and not (file_matches or net_matches):
        reasons.append('Suspicious processes executed (PowerShell/cmd/etc).')
        if verdict != 'CRITICAL':
            verdict = 'SUSPICIOUS'

    if staging and net_matches:
        reasons.append('Data staging (archive) observed and outbound connections matched.')
        verdict = 'CRITICAL'

    if net_matches and verdict != 'CRITICAL':
        reasons.append('Outbound connections to cloud or external IPs detected.')
        verdict = 'SUSPICIOUS'

    
    if verdict == 'BENIGN':
        reasons.append('No suspicious artifacts found for this session.')

    verdict_bundle = {'verdict': verdict, 'reasons': reasons}
    results.update(verdict_bundle)
    
    summary = {
        'verdict': results['verdict'],
        'reasons': results['reasons'],
        'auth_summary': auth_summary.get('auth_summary', []),
        'privileges': [{'detected': p['detected'], 'event_id': p['event'].get('event_id')} for p in privileges.get('privileges', [])],
        'suspicious_processes': [{'proc': s['proc'], 'cmd': s.get('cmd', ''), 'event_id': s['event'].get('event_id')} for s in processes.get('suspicious_processes', [])],
        'staging_processes': [{'proc': s['proc'], 'cmd': s.get('cmd', ''), 'event_id': s['event'].get('event_id')} for s in processes.get('staging_processes', [])],
        'file_access_matches': [{'path': m['path'], 'critical': m['critical'], 'event_id': m['event'].get('event_id')} for m in file_access_matches.get('file_access_matches', [])],
        'network_matches': [{'app': n['app'], 'dest': n['dest'], 'port': n['port'], 'reasons': n['reasons'], 'event_id': n['event'].get('event_id')} for n in network_matches.get('network_matches', [])],
        'usb_hits_count': len(usb_hits.get('usb_hits', [])),
        'notes': results.get('notes', [])
    }
    return summary

output = assign_verdict(file_access_matches, network_matches, privileges, processes, usb_hits, auth_summary)
""",
                "variables": {
                    "file_access_matches":"step.6.output",
                    "network_matches":"step.7.output",
                    "privileges":"step.4.output",
                    "processes":"step.5.output",
                    "usb_hits":"step.8.output",
                    "auth_summary":"step.3.output"
                }
            },
            "template":"""
{%- set verdict = (output.verdict or "").upper() -%}
{%- set reasons = output.reasons or [] -%}
{%- set auth_summary = output.auth_summary or [] -%}
{%- set privileges = output.privileges or [] -%}
{%- set suspicious_processes = output.suspicious_processes or [] -%}
{%- set staging_processes = output.staging_processes or [] -%}
{%- set file_access_matches = output.file_access_matches or [] -%}
{%- set network_matches = output.network_matches or [] -%}
{%- set usb_hits = output.usb_hits_count or 0 -%}

{%- if verdict == "BENIGN" -%}
No malicious or unauthorized behavior was identified in the analyzed Windows session. 
All observed authentication, file access, process creation, and network communication patterns 
align with typical system or administrative activity. The absence of suspicious artifacts 
such as critical file access, exfiltration indicators, or privilege misuse supports a benign assessment.
{%- elif verdict == "SUSPICIOUS" -%}
The session exhibited behaviors indicative of potential misuse or unauthorized activity. 
{{ reasons | join(' ') }}
{%- if suspicious_processes -%}
Observed processes include {{ suspicious_processes | map(attribute='proc') | unique | join(', ') }}, 
which are often leveraged for scripting, data staging, or administrative exploitation.
{%- endif -%}
{%- if privileges -%}
Elevated privileges ({{ privileges | map(attribute='detected') | sum(start=[]) | unique | join(', ') }}) 
were also assigned during this session, increasing the potential risk level.
{%- endif -%}
{%- if network_matches -%}
Outbound network communication to potentially sensitive destinations was recorded, 
suggesting a need for correlation with proxy or firewall logs.
{%- endif -%}
Overall, while not definitively malicious, these patterns warrant further review to 
validate their legitimacy and rule out early-stage compromise or misuse.
{%- elif verdict == "CRITICAL" -%}
The analysis indicates a high-risk or confirmed malicious session. 
{{ reasons | join(' ') }}
{%- if file_access_matches -%}
Sensitive file access was detected, including {{ file_access_matches | selectattr('critical') | map(attribute='path') | join(', ') }}.
{%- endif -%}
{%- if network_matches -%}
Suspicious network activity suggests potential data exfiltration or command-and-control communication.
{%- endif -%}
{%- if usb_hits > 0 -%}
Additionally, {{ usb_hits }} removable media interaction{{ 's' if usb_hits > 1 else '' }} were detected, 
which may indicate external data transfer attempts.
{%- endif -%}
Immediate containment, credential rotation, and forensic investigation are recommended to prevent further compromise.
{%- else -%}
No clear verdict could be determined from the available data. Further review of authentication, 
process, and file activity is advised to establish context.
{%- endif -%}
        """,
        "artifacts":[
            "{{output.verdict}}"
            
        ]
        } #9
    ]

def template():
    return """
{%- set verdict = step_8.verdict or "BENIGN" -%}
{%- set reasons = step_8.reasons or [] -%}
{%- set auth = step_8.auth_summary or [] -%}
{%- set privileges = step_8.privileges or [] -%}
{%- set suspicious_processes = step_8.suspicious_processes or [] -%}
{%- set staging_processes = step_8.staging_processes or [] -%}
{%- set file_access = step_8.file_access_matches or [] -%}
{%- set network = step_8.network_matches or [] -%}
{%- set usb_hits = step_8.usb_hits_count or 0 -%}

{%- set users = auth | map(attribute='user') | select | unique | list -%}
{%- set main_user = users[0] if users else "an unidentified account" -%}
{%- set unique_ips = auth | map(attribute='src_ip') | select | unique | list -%}
{%- set successful = auth | selectattr("event_id", "equalto", 4624) | list -%}
{%- set failed = auth | selectattr("event_id", "equalto", 4625) | list -%}

The Windows audit analysis examined the following artifacts and outcomes:\n

- Authentication logs: 
{%- if auth %}
    {%- if successful | length == 0 -%}
    Found only failed logon attempts associated with {{ main_user }}. As all requests were rejected, suggesting possible incorrect credentials or intentional probing. The absence of successful logons implies that unauthorized access was effectively prevented during this period.
    {%- elif failed | length == 0 -%}
    Multiple successful logon events were observed for the account {{ main_user }} ({{ unique_ips | join(', ') if unique_ips else 'N/A' }}). All are marked as Audit Success, reflecting routine authentication activity with no signs of anomalies or privilege misuse.
    {%- else -%}
    Mixed authentication activity detected for {{ main_user }} — both successful and failed attempts. Review IPs ({{ unique_ips | join(', ') if unique_ips else 'N/A' }}) for possible brute-force or credential reuse attempts.
    {%- endif -%}
{%- else -%}
Checked for logon events. No logon activity was observed.
{%- endif %}

{%- if privileges %}
- Privilege assignments: Checked for high-privilege events or escalations. Detected privilege changes ({{ privileges | map(attribute='detected') | sum(start=[]) | unique | join(', ') }}), suggesting potential administrative misuse.
{%- else %}
- Privilege assignments: Checked for high-privilege events or escalations. No privilege changes were found.
{%- endif %}

{%- if suspicious_processes %}
- Suspicious processes: Checked for high-risk processes. Detected {{ suspicious_processes | length }} process{{ 'es' if suspicious_processes|length > 1 else '' }} including {{ suspicious_processes | map(attribute='proc') | unique | join(', ') }}.
{%- else %}
- Suspicious processes: Checked for high-risk processes. No suspicious processes were observed.
{%- endif %}

{%- if staging_processes %}
- Data staging/archive commands: Checked for archive or staging activities. Detected {{ staging_processes | length }} event{{ 's' if staging_processes|length > 1 else '' }} possibly indicating data staging or exfiltration preparation.
{%- else %}
- Data staging/archive commands: Checked for archive or staging activities. No such activity was observed.
{%- endif %}

{%- if file_access %}
- File access: Checked for sensitive or critical file access. Detected {{ file_access | length }} event{{ 's' if file_access|length > 1 else '' }}, involving paths: {{ file_access | map(attribute='path') | unique | join(', ') }}.
{%- else %}
- File access: Checked for sensitive or critical file access. No critical or sensitive files were accessed.
{%- endif %}

{%- if network %}
- Network activity: Checked for suspicious outbound connections. Detected {{ network | length }} connection{{ 's' if network|length > 1 else '' }} potentially indicating data transfer or command-and-control activity.
{%- else %}
- Network activity: Checked for suspicious outbound connections. No anomalous network activity was observed.
{%- endif %}

{%- if usb_hits > 0 %}
- Removable media: Checked for USB or external drive interactions. Detected {{ usb_hits }} removable media connection{{ 's' if usb_hits > 1 else '' }}.
{%- else %}
- Removable media: Checked for USB or external drive interactions. No removable media activity was detected.
{%- endif %}

{%- if 'CRITICAL' in verdict %}
Summary Verdict: CRITICAL. These findings indicate high-risk or confirmed malicious activity requiring immediate containment.
{%- elif 'SUSPICIOUS' in verdict %}
Summary Verdict: SUSPICIOUS. Anomalies were observed that warrant further investigation to rule out unauthorized activity.
{%- else %}
Summary Verdict: BENIGN. No abnormal or malicious patterns were identified; all activities align with expected operational behavior.
{%- endif %}

{%- if reasons %}
Additional Notes: {{ reasons | join('; ') }}
{%- endif %}
"""