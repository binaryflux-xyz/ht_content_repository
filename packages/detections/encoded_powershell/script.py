def window():
    return None



def groupby():
    return None

def algorithm(event):
    # 4688: process creation
    if str(event.get('event_id') or '') != '4688':
        return 0.0

    proc = str(event.get('process_name') or '').lower()
    cmd  = str(event.get('process_command_line') or '').lower()

    # Only scope to PowerShell
    if ('powershell.exe' not in proc) and ('pwsh.exe' not in proc):
        return 0.0

    # red flags
    has_encoded = ('-enc' in cmd) or ('-encodedcommand' in cmd)
    has_bypass  = ('-ep bypass' in cmd) or ('-executionpolicy bypass' in cmd) or ('-nop' in cmd) or ('-noprofile' in cmd)

    dl_tokens   = [
        'invoke-webrequest', 'iwr ', 'wget ', 'curl ',
        'downloadstring', 'start-bitstransfer', 'new-object system.net.webclient'
    ]
    has_web_dl  = any(t in cmd for t in dl_tokens)
    has_url     = ('http://' in cmd) or ('https://' in cmd)

    if has_encoded or has_bypass or (has_web_dl and has_url):
        return 0.75

    return 0.0

def context(event):
    return (
        "Suspicious PowerShell execution detected. "
        "Process: " + str(event.get('process_name') or '') +
        " was executed with potentially risky parameters or commands: " +
        str(event.get('command_line') or '') +
        ". This may indicate malicious script execution, attempts to bypass security controls, "
        "or downloading and running unauthorized payloads on the host."
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Execution (TA0002)'

def technique():
    return 'Command and Scripting Interpreter (T1059/001)'

def artifacts():
    return stats.collect(['event_id','process_name','process_command_line'])

def entity(event):
    return {'derived': False, 'value': event.get('process_name'), 'type': 'process'}
