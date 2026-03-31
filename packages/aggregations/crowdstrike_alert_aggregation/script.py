def type() :
    return 'crowdstrike_alert_monitoring'

def columns() : #column names to be aggregated
    return ['severity_name','platform', 'tactic','device.hostname','device.site_name','display_name']

def archive() :
    return 'daily'

def uniquekey(message):
    return None

