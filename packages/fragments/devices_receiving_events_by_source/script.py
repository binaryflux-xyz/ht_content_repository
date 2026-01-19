# Format: Specifies the format for the data.
from datetime import datetime


def format():
    return "tabular"



def _format_timestamp(ts):
    try:
        ts = float(ts) / 1000.0   # convert ms → seconds
        dt = datetime.utcfromtimestamp(ts)
        return dt.strftime("%d-%m-%Y %H:%M")
    except:
        return ts



# this to return query to be used for rendering widget and its parameters
def query():
    return {
        'query': 'select max(timestamp) as last_activity_time, count(*) as total_events, source_device_name as host from aggregation_table  where source_device_name is not null and type = :type group by source_device_name',
        'parameters': {"type":"fortigate_realtime_server_monitor"}
    }


def _format_number(num):
    try:
        num = float(num)
    except:
        return num

    if num >= 1000000000:
        return "{:.1f}B".format(num / 1000000000.0)
    elif num >= 1000000:
        return "{:.1f}M".format(num / 1000000.0)
    elif num >= 1000:
        return "{:.1f}K".format(num / 1000.0)
    else:
        return int(num)

      
def render(results):
    if not results or len(results) == 0:
        raise Exception("no results found")

    # Assuming each row has consistent keys: 'provider', 'host', 'total'
    labels = ["Last Log", "Device", "Total Events"]
    data = []

    for row in results:
        last_activity_time = _format_timestamp(row.get("last_activity_time"))
        host = row.get("host", "")
        total = row.get("total_events", 0)
        formatted_total = _format_number(total)
        data.append([last_activity_time, host, formatted_total])

    return {
        "result": {
            "labels": labels,
            "data": data
        }
    }
