EVENT_IDS = {4688, 4957, 4953, 4663, 4656, 307}

def condition(event):
    if event['event_id'] in EVENT_IDS:
        return True
    else:
        return False





# def condition(event):
#     if event.get('event_id') == 4688 or event.get('event_id') == 4957 or event.get('event_id') == 4953 or event.get('event_id') == 4663 or event.get('event_id') == 4656 or event.get('event_id') == 307:
#         return True
#     else:
#         return False
