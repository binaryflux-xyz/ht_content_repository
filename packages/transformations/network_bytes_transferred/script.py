def transform(event) :
    sentbytes = (
        int(event.get("network_bytes_out"))
        if event.get("network_bytes_out") is not None
        else 0
    )
    receivedbytes = (
        int(event.get("network_bytes_in"))
        if event.get("network_bytes_in") is not None
        else 0
    )

    bytesTransferred = sentbytes + receivedbytes
    event["network_bytes_transferred"] = bytesTransferred

    return event  # Return the enriched event