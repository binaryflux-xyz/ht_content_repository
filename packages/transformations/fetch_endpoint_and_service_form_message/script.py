import re

def transform(event):
    message=event.get("event_message")

    # Regex to capture the endpoint and service name
    endpoint_match = re.search(r'access for\s+([^\s,]+)', message, re.IGNORECASE)
    service_match = re.search(r'service:\s*([\w-]+)', message, re.IGNORECASE)

    if endpoint_match:
        event["service_endpoint"] = endpoint_match.group(1).strip()

    if service_match:
        event["service_name"] = service_match.group(1).strip()

    return event