def condition(event):
    if event.get('event_id') == 5152 or event.get('event_id') == 5157 or event.get('event_id') == 7045 or event.get('event_id') == 4698 or event.get('event_id') == 5145 or event.get('event_id') == 4663 or event.get('event_id') == 5140 or event.get('event_id') == 4625 or event.get('event_id') == 805 or event.get('event_id') == 808 or event.get('event_id') == 4624:
        return True
    else:
        return False