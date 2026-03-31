def window():
    return "5m"

def groupby():
    return ["database_principal_name", "ip_address"]

def algorithm(event):
    query = (event.get('statement') or '').lower()

    if not query:
        return 0.0

    dump_patterns = [
        'select * into',    
        'into #',           
        'into temp',         
        'xp_cmdshell',      
        'sp_oacreate',       
        'backup database',   
        'dump ',             
    ]

    if any(p in query for p in dump_patterns):
        return 0.75

    if 'select' in query and 'into' in query:
        if stats.count('data_dump') >= 5:
            stats.resetcount('data_dump')
            return 0.75

    return 0.0

def context(event):
    return (
        "Potential data dump activity detected. User " +
        str(event.get('database_principal_name')) +
        " from IP " + str(event.get('ip_address')) +
        " executed queries indicating data being staged or dumped into tables or system locations."
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Collection (TA0009)'

def technique():
    return 'Data Staged (T1074)'


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
