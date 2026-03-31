# this to return default widget config
def configure():
    return {
        "searchable": False,
        "datepicker": False,
        "properties": {"type": "pie"},
        "dimension": {"x": 4, "y": 3, "width": 4, "height": 3}
    }

# this to return query to be used for rendering widget and its parameters
def query():

    return {
        "query": "SELECT tactic ,  COUNT(*) AS total FROM aggregation_table where type= :type GROUP BY tactic;",
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
    return{
        "sortcol":"total",
        "sortorder":"desc"    
    }


# this to return return formated results to render a widget
def render(data):
    transformed_data = []

    for item in data[:20]:
        transformed_data.append({
            "name": item["tactic"],
            "y": item["total"]
        })
    
    return {"result":transformed_data,"column":"tactic","label":"Tactic"}