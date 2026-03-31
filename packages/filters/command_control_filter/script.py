EVENT_IDS = {5156, 20225, 22, 5501}

def condition(event):
    if event['event_id'] in EVENT_IDS:
        return True
    else:
        return False





# def condition(event):
#     if event.get('event_id') ==  or event.get('event_id') ==  or event.get('event_id') ==  or event.get('event_id') == :
#         return True
#     else:
#         return False