import re
import traceback
# Precompile regex to improve performance
LOG_PATTERN = re.compile(r'(\S+)=("[^"]*"|\S+)')

def parse(message):
    try:
        message = message.strip()
        
        # Fast check for unmatched quotes before parsing
        if message.count('"') % 2 != 0:
            raise ValueError('Unmatched quotation marks found in the message.')

        # Use regex for high-performance key-value extraction
        log_dict = {key: value.strip('"') for key, value in LOG_PATTERN.findall(message)}

        return log_dict
    except Exception as e:
        print("ERROR WHILE PARSING: ", str(e))
        traceback.print_exc()
        return None 