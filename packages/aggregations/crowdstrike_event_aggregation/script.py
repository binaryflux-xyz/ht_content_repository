def type() :
    return 'crowdstrike_monitoring'

def columns() : #column names to be aggregated
    return ['event_type','event_action', 'service_name','source_ip']

def archive() :
    return 'daily'

def uniquekey(message):
    return None
