def type() :
    return 'crowdstrike_specific_alert__monitoring'

def columns() : #column names to be aggregated
    return ['resolution']

def archive() :
    return 'daily'

def uniquekey(message):
    return None

