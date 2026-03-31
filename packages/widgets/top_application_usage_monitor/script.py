# sample name -> widgets/accounts_compromised/script.py

# this to return default widget config
def configure():
    return {
        "searchable": False,
        "datepicker": True,
        "pagination": False,
        "properties": {"type": "bar", "onclick":"open_offcanvaspanel"}, 
        "dimension": {"x":0,"y":3,"width": 6, "height": 3}
    }

# this to return query to be used for rendering widget and its parameters
def query():
    return {
        'query': 'SELECT count(*) as count, applicationname from aggregation_table where applicationname is not null and type = :type group by applicationname',
        'parameters': {"type":"apps_detection_map"},
    }

# this to return filter queries based on filters selected by user and its parameters
def filters(filter):
    return None


# this to return free text search query and its parameters
def search(freetext):
    searchquery = ' "applicationname" ilike :applicationname '
    return {
        'searchquery': searchquery,
        'parameters': {'applicationname': '%' + freetext + '%'},
    }


# this to return sort query
def sort():
    return{
        "sortcol":"count",
        "sortorder":"desc"    
    }

def render(result):
    data = []
    categories = []
    counter=0

    for item in result:
        if(counter<10):
            categories.append(item["applicationname"])
            data.append(item["count"])
            counter=counter+1
        
    return {"result":{"series":[{'data':data}], 'categories': categories,"column":"applicationname","label":"Applicationname","uniquekey":["category"],"columnmap":["applicationname"],"type":"apps_detection_map"}}
