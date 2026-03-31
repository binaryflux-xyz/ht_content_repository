CLEAN_IP = {'103.21.65.164', '8.8.8.8'}



def condition(event):
    if event.get('destination_ip') in CLEAN_IP:
        return False
    else:
        return True
