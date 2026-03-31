import re as re3164

def parse(data):
    match = re3164.match(r"<(\d+)>(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) ([\w.-]+) (.*)", data)
    if not match:
        raise ValueError("Invalid RFC 3164 format")
    return {
        "priority": match.group(1),
        "timestamp": match.group(2),
        "host": match.group(3),
        "message": match.group(4)
    }
