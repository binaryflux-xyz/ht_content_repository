def window():
    return "5m"

def groupby():
    return ["database_principal_name", "ip_address"]

def algorithm(event):
    query = (event.get('statement') or '').lower()

    if not query:
        return 0.0

    export_patterns = [
        'bcp ',               
        'openrowset',         
        'bulk insert',        
        'xp_cmdshell',       
        'outfile',           
        'dump ',             
        'copy '              
    ]

    if any(p in query for p in export_patterns):
        return 0.75

    if 'select' in query:
        # no TOP / LIMIT → potentially large extraction
        if 'top' not in query and 'limit' not in query:
            if stats.count('large_select') >= 15:
                stats.resetcount('large_select')
                return 0.75

    rows = event.get('affected_rows')

    try:
        if rows and int(rows) > 100000:
            return 0.75
    except:
        pass

    return 0.0

def context(event):
    return (
        "Potential bulk data export detected. User " +
        str(event.get('database_principal_name')) +
        " from IP " + str(event.get('ip_address')) +
        " executed queries indicating large-scale data extraction or export."
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Exfiltration (TA0010)'

def technique():
    return 'Exfiltration Over Alternative Protocol (T1048)'

def artifacts():
    return stats.collect([
        'database_principal_name',
        'ip_address',
        'statement',
        'database_name'
    ])

def entity(event):
    return {
        'derived': False,
        'value': event.get('database_principal_name'),
        'type': 'accountname'
    }

