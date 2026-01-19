def condition(event):
    if event.get('event_id') == 4624 or event.get('event_id') == 4625 or event.get('event_id') == 4672 or event.get('event_id') == 4673 or event.get('event_id') == 4728 or event.get('event_id') == 4729 or event.get('event_id') == 1102 or event.get('event_id') == 4741:
        return True
    else:
        return False