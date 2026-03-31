# sample name -> widgets/accounts_compromised/script.py


# this to return default widget config
def configure():
    return {
        "searchable": True,
        "datepicker": False,
        "pagination": True,
        "properties": {"type": "table"},
        "dimension": {"x":8,"y":6,"width": 4, "height": 3},
    }




def query():
    return {
        "query": "SELECT  display_name as name,severity_name as severity_name, count(*) as count from aggregation_table where type = :type group by display_name,severity_name",
        "parameters": {"type":"crowdstrike_alert_monitoring"},
    }


# this to return filter queries based on filters selected by user and its parameters
def filters(filter):
    return None


# this to return free text search query and its parameters
def search(freetext):
    searchquery = ' "display_name" ilike :display_name '
    return {
        "searchquery": searchquery,
        "parameters": {"display_name": "%" + freetext + "%"},
    }


# this to return sort query
def sort():
    return {"sortcol": "count", "sortorder": "desc"}


def render(results):
    severity_colors = {
        "HIGH": "#ff4d4d",     # Red
        "MEDIUM": "#ffa500",   # Orange
        "LOW": "#2ecc71"       # Green
    }
    if not results or len(results) == 0:
        raise Exception("no results found")

    for result in results:
        severity = result.get("severity_name", "").upper()
        result["score"] = result["count"]
        result["color"] = "#02a8b5"
        result["column"]= "entity"
        result["label"]= "Hostname"
        result["criticality"]=severity
        result["color"] = severity_colors.get(severity, "#02a8b5")

        del result["count"]
        del result["severity_name"]

    columns = ["name", "score"]

    return {"result": {"columns": columns, "rows": results},"uniquekey":['name','description'],"columnmap":["source_ip","source_hostname"],"type":"hostname_entity_map"}
