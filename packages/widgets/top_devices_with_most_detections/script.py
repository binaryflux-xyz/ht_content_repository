# sample name -> widgets/accounts_compromised/script.py

# this to return default widget config
def configure():
    return {
        "searchable": False,
        "datepicker": True,
        "properties": {"type": "wordcloud","onclick":"not_open_offcanvaspanel"},
        "dimension": {"x":8,"y":0,"width": 4, "height": 3}
    }

# this to return query to be used for rendering widget and its parameters
def query():
    return {
        'query': 'select source_device_name as name, count (*) as weight from aggregation_table where source_device_name is not null and type = :type group by source_device_name',
        'parameters': {"type":"account_detection_map"},
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

def render(result):
    data = []
    categories = []
    counter=0

    for item in result:
        if(counter<20):
            data.append(item)
            counter=counter+1
        
    return {"result":data,"column":"source_device_name","label":"Accoutname","uniquekey":['name'],"columnmap":["source_account_name"],"type":"account_detection_map"}