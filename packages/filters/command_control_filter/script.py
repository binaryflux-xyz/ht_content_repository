def condition(event):
    if event.get('event_id') == 5156 or event.get('event_id') == 20225 or event.get('event_id') == 22 or event.get('event_id') == 5501:
        return True
    else:
        return False