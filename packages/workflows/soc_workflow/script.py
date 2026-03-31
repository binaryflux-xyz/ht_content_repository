# function to get the initial status of incident
def start():
    return "Open"

# function to know steps after current status
def workflow():
    return {
    "Open": [
        "Under Investigation"
    ],
    "Under Investigation": [
        "False Positive",
        "Confirmed",
        "Open"
    ],
    "False Positive": [
        "Closed",
        "Open"
    ],
    "Confirmed": [
        "Containment",
        "Open"
    ],
    "Eradicate & Recover": [
        "Post Incident Review",
        "Open"
    ],
    "Containment": [
        "Eradicate & Recover",
        "Open"
    ],
    "Post Incident Review": [
        "Closed",
        "Open"
    ]
}

# function to know when the incident is completed
def end():
    return "Closed"

# function to manage workflow actions
def config():
    return {}
