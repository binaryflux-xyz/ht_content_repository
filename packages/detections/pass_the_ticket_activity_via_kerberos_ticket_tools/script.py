def window():
    return '1d'

def groupby():
    return ['host']

def automate():
    return False

def algorithm(event):
    img = (event.get('process_name') or '').lower()
    cmd = (event.get('command_line') or '').lower()
    evt_id = event.get('event_id') or ''
    parent = (event.get('parent_process_name') or '').lower()

    ticket_tools = ['mimikatz.exe', 'sekurlsa.exe', 'kerberoast.exe', 'klist.exe', 'powershell.exe']
    ptt_cmds = ['kerberos', 'ticket', 'golden', 'silver', 'ptt', 'tgt', 'svc', 'service', 'krbtgt', '/ticket', 'kerberos::ptt', 'kerberos::golden', 'kerberos::list']
    kerb_event_ids = ['4768', '4769', '4770', '4771', '4624', '4672']

    tool_found = img in ticket_tools
    cmd_found = False
    for keyword in ptt_cmds:
        if keyword in cmd:
            cmd_found = True
            break
    is_tool = tool_found and cmd_found
    
    is_kerb_event = evt_id in kerb_event_ids
    sus_parent = parent.endswith(('wscript.exe', 'cscript.exe', 'powershell.exe'))

    if is_tool and (is_kerb_event or sus_parent):
        stats.count('ptt_attack')
        c = stats.getcount('ptt_attack')
        if c >= 2:
            return 1.0
        elif c == 1:
            return 0.75
    return 0.0

def context(event):
    proc = event.get('process_name') or 'Unknown'
    cmd = event.get('command_line') or 'N/A'
    evt = event.get('event_id') or 'N/A'
    par = event.get('parent_process_name') or 'Unknown'
    
    return (
        "A suspected Pass-the-Ticket attack (T1550.003) has been detected involving credential access tactics. "
        "Process '{0}' spawned by '{1}' executed suspicious command: '{2}'. "
        "Event ID {3} indicates Kerberos authentication activity. "
        "This is categorized under Credential Access (TA0006). "
        "Investigate immediately to verify if this is legitimate service account activity."
    ).format(proc, par, cmd, evt)

def criticality():
    c = stats.getcount('ptt_attack')
    if c >= 2:
        return 'CRITICAL'
    elif c == 1:
        return 'HIGH'
    return None

def tactic():
    return 'Credential Access (TA0006)'

def technique():
    return 'Pass the Ticket (T1550/003)'

def artifacts():
    return ['host', 'process_name', 'command_line', 'parent_process_name', 'event_id']

def entity(event):
    return {'derived': False, 'value': event.get('host'), 'type': 'device'}
