def window():
    return None


def groupby():
    return None

def algorithm(event):
    # Parse bytes if available as a field (some logs use 'bytes', 'bytes_sent', 'bytes_out')
    bytes_out = int(event.get('bytes', 0))
    
    if event.get('source_device_interface') == 'Internal' and event.get('destination_device_interface') == 'External':
        if bytes_out >= 35 * 1024 * 1024:  # 500 MB
            return 0.75
    return 0.0

  
def context(event_data):
    mb_transferred = int(event_data.get('bytes', 0)) / (1024 * 1024)
    return (
        "Detected a large data transfer of approximately " + str(mb_transferred) + " MB "
        "from internal host " + event_data.get('source_ip', 'unknown') +
        " to external destination IP " + event_data.get('destination_ip', 'unknown') + ". "
        "This activity occurred over service '" + event_data.get('service_id', 'unknown') + 
        "' and may indicate potential data exfiltration."
    )

def criticality():
    return 'HIGH'
def tactic():
    return 'Exfiltration (TA0010)'
def technique():
    return 'Exfiltration Over C2 Channel (T1041)'
def artifacts():
    return stats.collect(['source_ip', 'destination_ip', 'bytes_sent', 'service_id',])
def entity(event):
    return {'derived': False, 'value': event['source_ip'], 'type': 'ip'}
