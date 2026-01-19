def window():
    return None

def groupby():
    return None

# This can be wired to your TI pipeline at runtime
THREAT_INTEL = {
    "malicious_ja3": [],
    "malicious_ja4": [],
    "ja3_rarity": {}  # ja3 -> rarity score (0.0–1.0)
}

def algorithm(event):
    details = event.get("details") or {}
    ja3 = details.get("ja3_fingerprint")
    ja4 = details.get("ja4_fingerprint")

    if not ja3 and not ja4:
        return 0.0

    if ja3 in THREAT_INTEL["malicious_ja3"] or ja4 in THREAT_INTEL["malicious_ja4"]:
        return 0.95

    rarity = THREAT_INTEL["ja3_rarity"].get(ja3, 1.0)
    if rarity < 0.001:
        return 0.8

    return 0.0

def context(event):
    details = event.get("details") or {}
    ja3 = details.get("ja3_fingerprint")
    ja4 = details.get("ja4_fingerprint")
    fp = ja3 or ja4 or "unknown"

    return (
        "Rare or known malicious TLS JA3/JA4 fingerprint '{fp}' observed from {src} "
        "towards {host} ({url})."
    ).format(
        fp=fp,
        src=event.get("source_ip"),
        host=event.get("host"),
        url=event.get("url"),
    )

def tactic():
    return "Command and Control"

def technique():
    return "T1071.001 - Application Layer Protocol: Web Protocols"

def criticality():
    return "HIGH"


def artifacts():
    return stats.collect([
        "source_ip",
        "host",
        "url",
        "event_action"
    ])

def entity(event):
    return {
        "derived": False,
        "value": event.get("source_ip", "unknown"),
        "type": "ipaddress"
    }