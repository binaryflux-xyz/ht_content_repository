from datetime import datetime

def window():
    return None

def groupby():
    return None

def algorithm(event):
    process = (event.get('process_name') or '').lower()
    action = (event.get('event_action') or '').lower()
    timestamp = event.get('timestamp')
    print(timestamp)

    if process == 'sshd' and action == 'accepted' and timestamp:
        try:
            dt = datetime.utcfromtimestamp(float(timestamp)/1000)
            hour = dt.hour
            minute = dt.minute
        except:
            return 0.0

        if (
            (hour == 18 and minute >= 30) or
            (hour > 18 and hour < 23) or
            (hour == 23 and minute <= 30)
        ):
            return 0.50

    return 0.0



def context(event_data):
    return (
        "Successful SSH login detected during off-hours for user " +
        str(event_data.get('user')) +
        " on host " + str(event_data.get('host')) + " from source ip " + str(event_data.get('source_ip')) + " and port " + str(event_data.get('source_port')) +  
        ". This may indicate unauthorized access."
    )


def criticality():
    return 'MEDIUM'


def tactic():
    return 'Initial Access (TA0001)'


def technique():
    return 'Valid Accounts (T1078)'


def artifacts():
    return stats.collect(['host','user','source_ip','event_details', 'source_port', 'event_action', 'process_name'])


def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'user'}