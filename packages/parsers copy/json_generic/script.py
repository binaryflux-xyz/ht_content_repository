import json as jsonparser

def parse(data):
    try:
        return jsonparser.loads(data)
    except ValueError:
        raise ValueError("Invalid JSON format")
