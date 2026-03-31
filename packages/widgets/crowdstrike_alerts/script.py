import datetime

def configure():
    return {
        "searchable": False,
        "properties": {"type": "statcard","layout":"card","graphtype":"trend"},
        "dimension": {"x":4,"y":0,"width": 4, "height": 1}
    }


# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "SELECT timestampbyhour AS hour, COUNT(*) AS total_events FROM aggregation_table where type= :type GROUP BY hour;",
         'parameters': {"type":"crowdstrike_alert_monitoring"}
    }

  

# this to return filter queries based on filters selected by user and its parameters
def filters(filters):
    return None


# this to return free text search query and its parameters
def search(freetext):
    return None


# this to return sort query
def sort():
    return None



def render(results):

    hour_map = {}

    # Convert ms to formatted hour
    def format_hour(ms):
        dt = datetime.datetime.utcfromtimestamp(ms / 1000)
        return dt.strftime("%d %H:%M")

    # Accumulate counts from results
    for row in results:
        hour = format_hour(row["hour"])
        hour_map[hour] = hour_map.get(hour, 0) + row["total_events"]

    categories = []
    published_data = []
    total = 0

    # Normalize current time to start of hour
    now = datetime.datetime.utcnow().replace(minute=0, second=0, microsecond=0)

    # Build last 24 hours with zero fill
    for i in range(23, -1, -1):
        dt = now - datetime.timedelta(hours=i)
        hour_label = dt.strftime("%d %H:%M")

        categories.append(hour_label)

        count = hour_map.get(hour_label, 0)
        published_data.append(count)
        total += count

    series = [{
        "name": "Alerts Received",
        "data": published_data
    }]

    return {
        "result": {
            "categories": categories,
            "series": series,
            "total": total,
            "className": "dlp-dashboardstats"
        }
    }
