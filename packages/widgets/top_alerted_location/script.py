# sample name -> widgets/accounts_compromised/script.py

# this to return default widget config
def configure():
    return {
        "searchable": False,
        "datepicker": False,
        "properties": {"type": "treemap"},
        "dimension": {"x":8,"y":3,"width": 4, "height": 3}
    }
# this to return query to be used for rendering widget and its parameters
def query():
    return {
        'query': 'select distinct site_name  ,count(*) as weight FROM aggregation_table where type= :type GROUP BY site_name;',
         'parameters': {"type":"crowdstrike_alert_monitoring"}
    }



# this to return filter queries based on filters selected by user and its parameters
def filters(filter):
    return None


# this to return free text search query and its parameters
def search(freetext):
    
    return None


# this to return sort query
def sort():
    return{
        "sortcol":"weight",
        "sortorder":"desc"    
    }


def render(data):
    transformed_data = []


    for item in data[:10]:
        transformed_data.append({
            "name": item["site_name"],
            "value": item["weight"]
        })

    return {"result":transformed_data,"column":"email_from_address","label":"City"}
  