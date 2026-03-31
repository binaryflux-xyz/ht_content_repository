# this to return default widget config
def configure():
    return {
        "searchable": False,
        "datepicker": True,
        "pagination": False,
        "properties": {"type": "treemap"}, #,"onclick":"open_offcanvaspanel"
        "dimension": {"x": 6, "y": 6, "width": 6, "height": 3},
    }


# this to return query to be used for rendering widget and its parameters
def query():

    return {
        "query": """SELECT source_ip, SUM(TRY_CAST(network_bytes_transferred AS BIGINT)) as bytestransferred \
                from aggregation_table \
                where type = :type group by source_ip""",
        "parameters": {"type":"entity_bandwidth_map"},
    }


# this to return filter queries based on filters selected by user and its parameters
def filters(filter):
    return None


# this to return free text search query and its parameters
def search(freetext):
    searchquery = ' "source_ip" ilike :source_ip '
    return {
        "searchquery": searchquery,
        "parameters": {"source_ip": "%" + freetext + "%"},
    }


# this to return sort query
def sort():
    return {"sortcol": "bytestransferred", "sortorder": "DESC"}


# this to return return formated results to render a widget
def render(results):
    if not results or len(results) == 0:
        raise Exception("no results found")

    categories = []
    counter=0

    for result in results:
        if(counter<10):
            bytestransferred = int(result["bytestransferred"])
            bytes_transferred = round((bytestransferred / 1024), 2)
            entity = result["source_ip"]

            category = {"name": entity, "value": bytes_transferred}
            categories.append(category)
            counter=counter+1

    return {"result": categories,"column":"source_ip","label":"Entity","uniquekey":['name'],"columnmap":["source_ip"],"type":"entity_bandwidth_map"}
