def configure():
    return {
        "searchable": False,
        "properties": {
            "type": "statcard",
            "layout": "card",
            "graphtype": "bar"
        },
        "dimension": {"x": 8, "y": 0, "width": 4, "height": 1}
    }


# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "SELECT severity_name ,count(*) as criticalitycount FROM aggregation_table where type= :type GROUP BY severity_name",
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

# this to return return formated results to render a widget
def render(results):
    categories = ["HIGH", "MEDIUM", "LOW"]
    series = []
    total = 0

    criticality_map = {}

    # Build map in case-insensitive way
    for item in results:
        severity = item.get("severity_name", "")
        count = item.get("criticalitycount", 0)

        if severity:
            criticality_map[severity.upper()] = count

    # Fetch scores in required order
    for category in categories:
        count = criticality_map.get(category, 0)
        series.append(count)
        total += count

    return {
        "result": {
            "series": [{'data': series, "name": 'Detections'}],
            "categories": categories,
            "total": total
        }
    }

