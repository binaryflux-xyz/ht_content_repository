import re

# Core regex: matches key="value with spaces" or key=value
pattern = re.compile(r'(\w+)=("[^"]*"|\S+)')

invalid_pattern = re.compile(r'<\d+>')

def parse(data):
    # Check for invalid pattern first
    if invalid_pattern.search(data):
        raise ValueError("Incorrect data: " + data)
      
    parsed = {}
    errors = []

    for match in pattern.finditer(data):
        key, raw_val = match.group(1), match.group(2)

        # Clean up value
        val = raw_val.strip('"').strip()

        # Attempt type conversion
        if val.isdigit():
            val = int(val)
        else:
            try:
                if '.' in val and all(c.isdigit() or c == '.' for c in val):
                    val = float(val)
                elif val.lower() in ('true', 'false'):
                    val = val.lower() == 'true'
            except Exception:
                pass

        parsed[key] = val

    tokens = data.split()
    matched_keys = set(parsed.keys())
    for token in tokens:
        if '=' not in token:
            continue
        key = token.split('=')[0]
        if key not in matched_keys:
            errors.append(token)
    if errors:
        parsed["_unparsed"] = errors

    return parsed

