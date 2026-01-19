# Command Line: powershell.exe Set-Service -Name EventLog -StartupType Disabled
def window():
    return None

def groupby():
    return None

def investigate():
    return "windows_server_session_analyser"

def automate():
    return False

def algorithm(event_data):

    # Check conditions for disabling event log
    if (event_data.get('event_id') == "4688" and('eventlog' in event_data.get('process_command_line') or  'disabled' in event_data.get('process_command_line'))):
        return 0.50
    return 0.0


def context(event_data):
    source_account_name=event_data.get('source_account_name')
    source_account_domain=event_data.get('source_account_domain')
    process_command_line =event_data.get('process_command_line'),
    process_id= event_data.get('process_id'),
    process_name= event_data.get('process_name'),
    creator_process_id= event_data.get('creator_process_id')
    return "The Windows event logging system was disabled. This action was performed by "+ (source_account_name if source_account_name else 'an unknown account')+" from "+ (source_account_domain if source_account_domain else 'an unknown domain')+", using process "+(process_name if process_name else 'None')+" (ID:"+ (process_id if process_id else 'None')+"). The creator process ID involved was "+(creator_process_id  if creator_process_id else 'None')+". Command line used: " +(process_command_line if process_command_line else 'not available')+"."
    


def criticality():
    return 'MEDIUM'


def tactic():
    return 'Defense Evasion (TA0005)'


def technique():
    return 'Disable Windows Event Logging (T1562/002)'


def artifacts():
    try:
        return stats.collect(['event_id','source_security_id','source_account_name','source_account_domain','creator_process_name','source_logon_id','process_command_line','process_name','creator_process_id'])
    except Exception as e:
        raise e
    
def entity(event):
    return {'derived': False,
            'value': event.get('source_account_name'),
            'type': 'accountname'}