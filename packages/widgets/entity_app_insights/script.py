# sample name -> widgets/accounts_compromised/script.py
import time

# this to return default widget config
def configure():
    return {
        "searchable": False,
        "datepicker": True,
        "pagination": False,
        "properties": {"type": "column" ,"onclick":"open_offcanvaspanel"},
        "dimension": {"x": 6, "y": 3, "width": 6, "height": 3},
    }



# this to return query to be used for rendering widget and its parameters
def query():
    return {
        "query": "SELECT source_ip,applicationname,count(*) as frequency \
                from aggregation_table \
                where source_ip in (select source_ip from \
                    (select source_ip, count(*) as freq from aggregation_table \
                    where source_ip is not null \
                    group by source_ip order by freq desc limit 10))\
                and applicationname in (select applicationname from \
                    (select applicationname, count(*) as f from aggregation_table \
                    where applicationname is not null \
                    group by applicationname order by f desc limit 100))\
                and type = :type group by source_ip,applicationname",
        "parameters": {"type":"entity_app_frequency_map"},
    }

# this to return filter queries based on filters selected by user and its parameters
def filters(filter):
    filterqueries = []
    parameters = {}
    if filter:
        if filter.get("applicationname"):
            filterqueries.append("applicationname in (:applicationname)")
            parameters["applicationname"] = filter.get("applicationname")
    return {"filterqueries": filterqueries, "parameters": parameters}


# this to return free text search query and its parameters
def search(freetext):
    return None


# this to return sort query
def sort():
    return None

# this to return return formated results to render a widget
def render(results):

    entity_frequencies = {}
    for item in results:
        entity = item['source_ip']
        frequency = item['frequency']
        if entity in entity_frequencies:
            entity_frequencies[entity] += frequency
        else:
            entity_frequencies[entity] = frequency

    # Step 2: Sort the entities by total frequency and select the top 10
    top_entities = sorted(entity_frequencies.items(), key=lambda x: x[1], reverse=True)[:10]
    top_entities = [entity for entity, _ in top_entities]

    # Step 3: Create the categories list
    categories = top_entities

    # Step 4: Extract unique application names for the top entities
    application_names = sorted(set(item['applicationname'] for item in results if item['source_ip'] in top_entities))

    # Step 5: Create the series structure
    series = []
    for app_name in application_names:
        app_data = {
            'name': app_name,
            'data': [next((item['frequency'] for item in results if item['applicationname'] == app_name and item['source_ip'] == entity), 0) for entity in top_entities]
        }
        series.append(app_data)
        
    return {"result": {"categories":categories,"series":series},"column":"entity","label":"Entity","uniquekey":["category","name"],"columnmap":["source_ip","applicationname"],"type":"entity_app_frequency_map"}


