def type() :
    return 'crowdstrike_process_lineage_alert__monitoring'

def columns() : #column names to be aggregated
    return ['resolution']

def archive() :
    return 'daily'

def uniquekey(message):
    return None

