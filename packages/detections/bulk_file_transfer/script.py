def window():
    return '5m'

def groupby():
    return ['user']

def algorithm(event):
    size = int(event.get('file_size') or 0)

    if size > 1000000000:  # 1GB
        return 0.75

    return 0.0

def context(event):
    return (
        "Large file transfer detected by user " +
        str(event.get('user')) +
        " with size " + str(event.get('file_size'))
    )

def criticality():
    return 'HIGH'

def tactic():
    return 'Exfiltration (TA0010)'

def technique():
    return 'Exfiltration Over Network (T1041)'

def artifacts():
    return stats.collect(['user','file_name','file_size','destination'])

def entity(event):
    return {'derived': False, 'value': event.get('user'), 'type': 'user'}