# this to return default widget config
def configure():
    return {
        "searchable": False, #Boolean value depending whether the widget is searchable or not
        "datepicker": False,
        "properties": {"type": "fatalwidget","layout": "conciselayout"},
        "dimension": {"x": 0, "y": 14, "width": 12, "height": 3} #dimensions of widget on GRID
    }

# this to return query to be used for rendering widget and its parameters
# def query():
#     return {
#         "query": """
#             SELECT 
#                 timestamp AS time,
#                 source_ip AS ipaddress,
#                 event_level AS alert,
#                 event_details AS message
#             FROM 
#                 aggregation_table
#             WHERE
#                 event_level in (0, 1, 2, 3, 4)
#                 AND timestamp IS NOT NULL
#                 AND source_ip IS NOT NULL
#                 AND event_level IS NOT NULL
#                 AND event_details IS NOT NULL
#                 AND type = :type
#             GROUP BY 
#                 timestamp, source_ip, event_level, event_details
#             LIMIT 200
#         """,
#         "parameters": {"type":"event_level_host"},
#     }
def query():
    return {
        "query": """
            SELECT 
                MAX(timestamp) AS time,
                source_country AS country,
                event_details AS message,
                event_level AS alert,
                COUNT(*) AS count
            FROM 
                aggregation_table
            WHERE
                event_level IN (0, 1, 2, 3, 4, 5)
                AND timestamp IS NOT NULL
                AND source_country IS NOT NULL
                AND event_level IS NOT NULL
                AND event_details IS NOT NULL
                AND type = :type
            GROUP BY 
                source_country, event_level, event_details
            ORDER BY 
                time DESC
            LIMIT 200
        """,
        "parameters": {"type": "event_level_host"},
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
# def render(results):
#     if len(results) > 10:
#         results = results[:10]  # Limit to the first five records        
#     for result in results:
#         result['time']=result['insert_date']
#     columnList=['time', 'source_ip', 'event_details', 'event_level'];
    
#     return {"result": results,"columns":columnList}
# import datetime

# def render(results):
#     # Only include relevant Fortigate levels (0–4)
#     log_levels = {
#         "emergency": 0,
#         "alert": 1,
#         "critical": 2,
#         "error": 3,
#         "warning": 4
#     }
#     # Compatible for all Python 2 versions
#     reverse_log_levels = dict((v, k) for k, v in log_levels.items())

#     for result in results:
#         # Convert timestamp (ms → readable datetime)
#         if 'time' in result and isinstance(result['time'], (int, float, long)):
#             result['time'] = datetime.datetime.fromtimestamp(float(result['time']) / 1000).strftime('%Y-%m-%d %H:%M:%S')

#         # Convert numeric event level to text
#         if 'alert' in result:
#             result['alert'] = reverse_log_levels.get(result['alert'], 'unknown')

#     columnList = ['time', 'ipaddress', 'message', 'alert']
#     return {"result": results, "columns": columnList}
import datetime

# def render(results):
#     log_levels = {
#         "emergency": 0,
#         "alert": 1,
#         "critical": 2,
#         "error": 3,
#         "warning": 4,
#         "notice": 5
#     }
#     color_map = {
#        "#ff0303":0,
#      "#ff0303a7":1,
#      "#ab0707a7":2,
#       "#f5654c":3,
#       "#d2c425":4,
#        "#098b39":5
#     }
  
#     reverse_log_levels = dict((v, k) for k, v in log_levels.items())
#     reverse_color_map = dict((v, k) for k, v in color_map.items())

#     for result in results:
#         # Convert milliseconds to readable timestamp
#         if 'time' in result and isinstance(result['time'], (int, float, long)):
#             result['time'] = datetime.datetime.fromtimestamp(
#                 float(result['time']) / 1000
#             ).strftime('%Y-%m-%d %H:%M:%S')

#         # Convert numeric alert to human-readable string
#         if 'alert' in result:
#             # result['alert'] = reverse_log_levels.get(result['alert'], 'unknown')
#             result['color'] = reverse_color_map.get(result['alert'], 'grey')
#             result['showcolorclass'] = "alert"
  


#     # Ensure columns appear exactly in the requested order
#     columnList = ['time', 'country', 'message', 'alert', 'count']

#     return {"result": results, "columns": columnList}
def render(results):
    # Define log level names and corresponding numeric codes
    log_levels = {
        "emergency": 0,
        "alert": 1,
        "critical": 2,
        "error": 3,
        "warning": 4,
        "notice": 5
    }

    # Map numeric event levels to their colors
    color_map = {
        0: "#ff0303",     # emergency
        1: "#ff0303a7",   # alert
        2: "#ab0707a7",   # critical
        3: "#f5654c",     # error
        4: "#d2c425",     # warning
        5: "#098b39"      # notice
    }

    # Create reverse lookup for converting numeric alert → name
    reverse_log_levels = {v: k for k, v in log_levels.items()}

    # Process all results
    for result in results:
        # Convert milliseconds to readable timestamp
        if 'time' in result and isinstance(result['time'], (int, float, long)):
            result['time'] = datetime.datetime.fromtimestamp(
                float(result['time']) / 1000
            ).strftime('%Y-%m-%d %H:%M:%S')

        # Convert numeric alert to readable text and assign color
        if 'alert' in result:
            try:
                # Convert "5" → 5 (handles string or float)
                level = int(result['alert'])
            except (ValueError, TypeError):
                continue  # skip bad data safely

            # Only handle valid levels (0–5)
            if level in reverse_log_levels:
                result['alert'] = reverse_log_levels[level]  # Replace with name
                result['color'] = color_map[level]           # Assign color
                result['showcolorclass'] = "alert"
            else:
                continue  # skip anything outside 0–5

    # Define column order for widget rendering
    columnList = ['time', 'country', 'message', 'alert', 'count']

    return {"result": results, "columns": columnList}