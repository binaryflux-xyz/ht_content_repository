def steps():
    return [
    {
        "name": "execute_python",
        "parameters": {
            "code": 
"""
def extract_ipaddress(event):
    keys = [
        "source_ip",
        "source_ip_set",
        "destination_ip",
        "destination_ip_set",
        "source_remote_ip",
    ]

    result = []

    for key in keys:
        value = event.get(key)

        if not value:
            continue

        # If value is a list → extend
        if isinstance(value, list):
            result.extend(value)

        # If value is a single IP string → append
        elif isinstance(value, str):
            result.append(value)

    return result

output = extract_ipaddress({"source_ip":source_ip,"source_ip_set":source_ip_set,"destination_ip":destination_ip,"destination_ip_set":destination_ip_set,"source_remote_ip":source_remote_ip,})

""",
            "variables": {
                "source_ip": "event.source_ip",
                "source_ip_set": "event.source_ip.set",
                "destination_ip": "event.destination_ip",
                "destination_ip_set": "event.destination_ip.set",
                "source_remote_ip": "event.source_remote_ip",
            }
        },
        
        "template": "Extracted ip addresses from the event are {{ output }}"
    }, #1
    {
        "name": "execute_python",
        "parameters": {
            "code": """

import ipaddress

def is_internal_ip(ip_str: str) -> bool:
    try:
        if not ip_str:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

def is_external_ip(ip_str: str) -> bool:
    return not is_internal_ip(ip_str)


def find_external_ip(all_inputs) :
    external_ips = []

    for ip in all_inputs:
        if is_external_ip(ip):
            external_ips.append(ip)

    return list({ip for ip in external_ips if ip})

output = find_external_ip(ip_addresses)

""",
            "variables": {
                "ip_addresses": "step.1.output"
            }
        },
        "template": "{%- if output is none -%}\nNo any external IP address was found for analysis.\n{%- else -%}\nThe IP address {{ output }} are external ip addresses.\n{%- endif -%}"
    }, #2
    {
        "name": "evaluate",
        "parameters": {
            "step": 2,
            "condition": "output is not None",
            "if_step": 4,
            "else_step": 20
        },
        "template": "{{ 'External IP detected, so the process moves to step 5 for further analysis.' if output else 'As no any external IP Address detected, the process stops here.' }}"
    }, #3
    {
        "name": "action",
        "parameters": {
            "action": "AlienVault",
            "fields": {
                "client.ip": {
                    "step": 2,
                    "path": "output"
                }
            }
        },
        "template": "{%- if output and output.responses -%}\nAlienVault analysis finished.\n{% for ip, resp in output.responses.items() -%}\n{%- set stats = resp.pulse_info.count if resp and resp.pulse_info else {}-%}\n{{ ip }} - Malicious: {{ stats }}\n{% endfor -%}\n{% else -%}\nNo AlienVault data available.\n{% endif %}"
    }, #4
    {
        "name": "action",
        "parameters": {
            "action": "LookupIpv4",
            "fields": {
                "ipaddress": {
                    "step": 2,
                    "path": "output"
                }
            }
        },
        "template": """
{%- for ip, data in output.responses.items() -%}
    {%- if data.rows and data.rows|length > 0 -%}
        {% set row = data.rows[0] %}
The LookupIpv4 action was triggered by IP address {{ ip }}, which returned geographical data including continent ({{ row[3] }}) and country ISO code ({{ row[4] }}), indicating the IP is from {{ row[5] }}.
    {%- else -%}
No geographical data was found for IP address {{ ip }}.
    {%- endif -%}
{%- endfor -%}
"""
    }, #5
    {
        "name": "action",
        "parameters": {
            "action": "BlacklistedCountries",
            "fields": {
                "country": {
                    "step": 5,
                    "path": "output.responses.*.rows[0][5]"
                }
            }
        },
        "template": "{%- set ns = namespace(blacklisted=[], all_locations=[]) -%}\n\n{%- for country, data in output.responses.items() -%}\n    {%- set ns.all_locations = ns.all_locations + [country] -%}\n    {%- if data.rows | length > 0 -%}\n        {%- set ns.blacklisted = ns.blacklisted + [country] -%}\n    {%- endif -%}\n{%- endfor %}\n\n{%- if ns.blacklisted | length > 0 -%}\nThe geolocation ({{ ns.blacklisted | join(', ') }}) extracted from an IP address above is BLACKLISTED.\n{%- else -%}\nThe geolocation ({{ ns.all_locations | join(', ') }}) extracted from an IP address above is not blacklisted.\n{%- endif %}"
    }, #6
    {
        "name": "action",
        "parameters": {
            "action": "EventSession",
            "fields": {
                "event->>'provider'": {
                    "step": 0,
                    "path": "streamprovider"
                }
            }
        },
        "template": "The log details a series of network security events captured by the FortiGate firewall, showing repeated activity associated with a common source or destination. The close sequence of timestamps indicates these events occurred in rapid succession, suggesting a brief burst of network traffic or automated session activity. This pattern may reflect user-driven access, policy enforcement, or a batch of connections initiated within a short monitoring window."
    }, #7
    {
        "name": "execute_python",
        "parameters": {
            "code": "import shlex\nfrom datetime import datetime\nfrom typing import Any, Dict, List, Optional\n\ndef _parse_time(ts: Any) -> Optional[datetime]:\n    if ts is None:\n        return None\n    if isinstance(ts, datetime):\n        return ts\n    # Try common FortiGate formats (ISO8601 or epoch seconds)\n    try:\n        if isinstance(ts, (int, float)):\n            return datetime.utcfromtimestamp(float(ts))\n        # Attempt ISO parsing\n        return datetime.fromisoformat(str(ts).replace('Z', '+00:00'))\n    except Exception:\n        return None\n\ndef _parse_fortigate_kv_message(message: str) -> Dict[str, Any]:\n    data: Dict[str, Any] = {}\n    try:\n        tokens = shlex.split(message)\n    except Exception:\n        tokens = message.split()\n    for tok in tokens:\n        if '=' not in tok:\n            continue\n        k, v = tok.split('=', 1)\n        # Trim surrounding quotes if any\n        if len(v) >= 2 and ((v[0] == '\"' and v[-1] == '\"') or (v[0] == \"'\" and v[-1] == \"'\")):\n            v = v[1:-1]\n        # Cast obvious ints\n        if v.isdigit():\n            try:\n                data[k] = int(v)\n                continue\n            except Exception:\n                pass\n        # Cast floats for large epoch-like numbers (keep as str if fails)\n        try:\n            if '.' in v and v.replace('.', '', 1).isdigit():\n                data[k] = float(v)\n                continue\n        except Exception:\n            pass\n        data[k] = v\n    return data\n\ndef _normalize_fortigate_event(e: Dict[str, Any]) -> Optional[Dict[str, Any]]:\n    # If already normalized (heuristic)\n    if any(k in e for k in ('src_ip', 'dst_ip', 'dst_port', 'protocol')) and 'message' not in e:\n        return e\n\n    msg = e.get('message')\n    if not isinstance(msg, str):\n        return e if isinstance(e, dict) else None\n\n    # Quick check for FortiGate kv format\n    if 'srcip=' in msg and 'dstip=' in msg:\n        kv = _parse_fortigate_kv_message(msg)\n\n        # Time resolution: prefer eventtime (often ns) else date+time (+ tz)\n        ts: Optional[datetime] = None\n        eventtime = kv.get('eventtime')\n        if isinstance(eventtime, (int, float)):\n            # Many FortiGate logs use nanoseconds; fall back to seconds if small\n            try:\n                ts_val = float(eventtime)\n                # Heuristic: if ts looks like nanoseconds (>= 1e12), convert\n                if ts_val > 1e12:\n                    ts = datetime.utcfromtimestamp(ts_val / 1_000_000_000)\n                else:\n                    ts = datetime.utcfromtimestamp(ts_val)\n            except Exception:\n                ts = None\n        if ts is None:\n            dt_str = ''+kv.get('date','')+' '+ kv.get('time','')\n            ts = _parse_time(dt_str)\n\n        # Protocol mapping\n        proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}\n        proto_val = kv.get('proto')\n        protocol = None\n        try:\n            if isinstance(proto_val, str) and proto_val.isdigit():\n                proto_val = int(proto_val)\n            protocol = proto_map.get(proto_val, str(proto_val) if proto_val is not None else None)\n        except Exception:\n            protocol = None\n\n        # Action mapping\n        raw_action = str(kv.get('action', e.get('action', ''))).lower()\n        action_map = {\n            'accept': 'ALLOW',\n            'close': 'ALLOW',\n            'pass': 'ALLOW',\n            'blocked': 'DENY',\n            'deny': 'DENY',\n            'block': 'DENY',\n            'client-rst': 'ALLOW',\n            'server-rst': 'ALLOW',\n        }\n        action = action_map.get(raw_action, raw_action.upper() if raw_action else None)\n\n        # Bytes: we use sentbyte as our 'bytes' metric (as per module docstring)\n        bytes_val = kv.get('sentbyte')\n        try:\n            bytes_val = float(bytes_val) if bytes_val is not None else 0\n        except Exception:\n            bytes_val = 0\n\n        norm: Dict[str, Any] = {\n            'time': ts.isoformat() if isinstance(ts, datetime) else None,\n            'action': action,\n            'src_ip': kv.get('srcip'),\n            'dst_ip': kv.get('dstip'),\n            'src_port': kv.get('srcport'),\n            'dst_port': kv.get('dstport'),\n            'protocol': protocol,\n            'bytes': bytes_val,\n            'policy_id': kv.get('policyid'),\n            'policy_name': kv.get('policyname'),\n            'device_name': kv.get('devname'),\n            'service': kv.get('service') or kv.get('app'),\n        }\n        # Optional enrichment from kv\n        threat_tags: List[str] = []\n        apprisk = str(kv.get('apprisk', '')).lower()\n        if apprisk in {'elevated', 'high', 'critical'}:\n            threat_tags.append('elevated_risk_app')\n        if str(kv.get('logid', '')).startswith('0316') and action == 'DENY':\n            threat_tags.append('webfilter_block')\n        if threat_tags:\n            norm['threat_tags'] = threat_tags\n\n        return norm\n\n    # Fallback: if message looks like JSON we might extend here later; for now return original\n    return e\n\ndef _preprocess_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:\n    normalized: List[Dict[str, Any]] = []\n    for e in events or []:\n        try:\n            if e.get('provider') == 'Fortigate':\n                n = _normalize_fortigate_event(e)\n                if n is not None:\n                    normalized.append(n)\n        except Exception:\n            # Best-effort: skip bad event\n            continue\n    return normalized\n\noutput = _preprocess_events(session)",
            "variables": {
                "session": "step.7.output.result"
            }
        },
        "template": "This step parsed and normalized raw FortiGate firewall logs into structured JSON data. It extracted essential fields such as source and destination IPs, ports, protocols, actions, timestamps, and policy details while omitting redundant attributes. The logs were converted from FortiGate’s key–value format into clean dictionaries, with timestamps accurately interpreted and protocol or action codes mapped to readable values. Additional contextual tags like elevated risk or web filter blocks were added, resulting in a uniform, enriched dataset ready for downstream analysis."
    }, #8
    {
        "name": "execute_python",
        "parameters": {
            "code": "from statistics import mean\nfrom typing import Any, Dict, List\n\ndef _safe_mean(values: List[float]) -> float:\n    return mean(values) if values else 0.0\n\ndef aggregate_threatintel(ipreports: Dict[str, Any]) -> Dict[str, Any]:\n    malicious = 0\n    for ip, report in ipreports.items():\n        try:\n            if report.get('pulse_info').get('count') > 0:\n                malicious += report.get('pulse_info').get('count')\n        except Exception as e:\n            pass\n    return malicious\n    \n\ndef aggregate_metrics(events: List[Dict[str, Any]], ipreports: Dict[str, Any]) -> Dict[str, Any]:\n    return {\n        'event_count': len(events),\n        'deny_count': sum(1 for e in events if str(e.get('action', '')).upper() == 'DENY'),\n        'allow_count': sum(1 for e in events if str(e.get('action', '')).upper() == 'ALLOW'),\n        'unique_dest_ports': len({e.get('dst_port') for e in events if e.get('dst_port') is not None}),\n        'avg_bytes_sent': _safe_mean([float(e.get('bytes', 0) or 0) for e in events]) if events else 0.0,\n        'threat_tags': list({t for e in events for t in (e.get('threat_tags') or [])}),\n        'protocol': events[0].get('protocol') if events else None,\n        'malicious': aggregate_threatintel(ipreports)\n    }\noutput = aggregate_metrics(events, ipreports)\n\n\n",
            "variables": {
                "events": "step.8.output",
                "ipreports": "step.4.output.responses"
            }
        },
        "template": "{%- if not output -%}\nNo security-relevant events were identified during the analysis window.\n{%- else -%}\nA total of {{ output.event_count }} network events were observed during the analysis period. \nOf these, {{ output.allow_count }} events were permitted and {{ output.deny_count }} were blocked by the security controls.\n{%- if output.protocol %}\n The predominant protocol identified across the events was {{ output.protocol }}.\n{%- endif %}\n Traffic was recorded across {{ output.unique_dest_ports }} distinct destination ports, indicating the breadth of service interaction.\n{%- if output.avg_bytes_sent and output.avg_bytes_sent > 0 %}\n The average data transfer volume per event was approximately {{ \"%.2f\"|format(output.avg_bytes_sent) }} bytes.\n{%- endif %}\n{%- if output.threat_tags and output.threat_tags|length > 0 %}\n Threat intelligence mapping associated the activity with the following indicators or classifications: {{ output.threat_tags | sort | join(', ') }}.\n{%- else %}\n No threat intelligence indicators were associated with the observed events.\n{%- endif %}\n{%- endif -%}"
    }, #9
    {
        "name": "execute_python",
      "parameters": {
           "code": 
"""
from typing import Any, Dict, List

WEIGHTS = {
    'rule_port_scan': 30,
    'rule_ip_malicious': 30,
    'rule_blacklisted_country': 25,
    'rule_data_exfil': 30,
    'rule_fw_tag_malicious': 35,
    'rule_high_risk_port_allow': 20,
    'rule_high_deny_ratio': 10,
    'rule_beacon_like': 15,
}

def apply_rules(metrics: Dict[str, Any], intel: Dict[str, Any]) -> Dict[str, Any]:

    risk_score = 0
    triggered_rules: List[str] = []

    deny_ratio = (metrics.get('deny_count', 0)/metrics.get('event_count', 0))*100
    # 1. Port scan detection (baseline)
    if deny_ratio > 50 and metrics.get('unique_dest_ports', 0) > 20:
        triggered_rules.append('Port Scan Detected')
        risk_score += WEIGHTS['rule_port_scan']

    # 2. Outbound malicious connection (IP Report)
    if metrics.get('malicious', 0) > 0:
        triggered_rules.append('Destination marked malicious in Report')
        risk_score += WEIGHTS['rule_ip_malicious']

    # 4. Blacklisted location (GeoIP)
    if intel.get('blacklisted_country'):
        country = intel.get('blacklisted_country')
        triggered_rules.append(f'Destination in blacklisted country {country}')
        risk_score += WEIGHTS['rule_blacklisted_country']

    # 5. High data exfiltration
    if metrics.get('avg_bytes_sent', 0) > 1_000_000:
        triggered_rules.append('Possible data exfiltration')
        risk_score += WEIGHTS['rule_data_exfil']

    # 6. Threat tags from firewall logs
    if any(tag in {'c2', 'malware', 'phishing'} for tag in metrics.get('threat_tags', [])):
        triggered_rules.append('Firewall tag indicates malicious activity')
        risk_score += WEIGHTS['rule_fw_tag_malicious']

    return {'risk_score': risk_score, 'triggered_rules': triggered_rules, 'intel':intel}


output = apply_rules(metrics, {'blacklisted_country': blacklisted_country[0] if blacklisted_country else None, 'country': country if country else None})
""",
            "variables": { 
                "metrics": "step.9.output", 
                "country": "step.5.output.responses.*.rows[0][5]", 
                "blacklisted_country": "step.6.output.responses.*.rows[0]" 
            }
        },
        "template": "{%- set triggered_rules = output.triggered_rules or [] -%}\n{%- set intel = output.intel or {} -%}\n{%- set risk_score = output.risk_score or 0 -%}\n\n{%- if triggered_rules|length == 0 -%}\nThe analyzed network activity shows no indications of scanning behavior, data exfiltration, or malicious communication attempts. No threat intelligence or firewall alerts were triggered during this observation period.\n{%- else -%}\nThe analysis identified {{ triggered_rules|length }} notable event(s): {{ triggered_rules | join('; ') }}.\n{%- if intel.malicious and intel.malicious > 0 -%}\nThreat intelligence reports indicate {{ intel.malicious }} destination(s) classified as malicious by VirusTotal.\n{%- endif -%}\n{%- if intel.blacklisted_country -%}\nOne or more destinations are located in a restricted geography, identified as {{ intel.blacklisted_country }}.\n{%- endif -%}\nThe computed cumulative risk score from triggered indicators is {{ risk_score }}, reflecting the combined impact of observed behaviors.\n{%- endif -%}"
    }, #10
    {
        "name": "execute_python",
        "parameters": {
            "code": "from typing import Dict\n\nCRIT_THRESHOLDS = {\n    'ignore': 30,  \n    'medium': 60,\n}\n\ndef determine_criticality(risk_score: int, metrics: Dict[str, Any], intel: Dict[str, Any]) -> str:\n    # Base on risk score thresholds\n    if risk_score < CRIT_THRESHOLDS['ignore']:\n        criticality = 'Ignore'\n    elif risk_score < CRIT_THRESHOLDS['medium']:\n        criticality = 'Medium'\n    else:\n        criticality = 'High'\n\n    # Escalation rules: malicious VT or blacklisted location/IP → at least Medium/High\n    if metrics.get('malicious', 0) > 0 or intel.get('blacklisted_location') or intel.get('blacklisted_ip'):\n        criticality = 'High' if risk_score >= 50 else max(criticality, 'Medium', key=lambda x: ['Ignore', 'Medium', 'High'].index(x))\n\n    return criticality\noutput = determine_criticality(risk_score, metrics, intel)",
            "variables": {
                "metrics": "step.9.output",
                "intel": "step.10.output.intel",
                "risk_score": "step.10.output.risk_score"
            }
        },
        "template": "{%- set criticality = output or 'Unknown' -%}\n\n{%- if criticality == 'Ignore' -%}\nThe analyzed event is classified as low priority, indicating minimal risk and no immediate signs of malicious or suspicious behavior.\n{%- elif criticality == 'Medium' -%}\nThe analyzed event is classified as medium priority, suggesting potentially unusual or noteworthy activity that warrants further observation.\n{%- elif criticality == 'High' -%}\nThe analyzed event is classified as high priority, indicating strong evidence of risky or malicious behavior requiring prompt review.\n{%- else -%}\nThe criticality level of the analyzed event could not be determined due to insufficient data.\n{%- endif -%}",
        "artifacts":[
            "{{output}}"
            
        ]
    }, #11
    {
        "name": "execute_python",
        "parameters": {
            "code": "from typing import Any, Dict, List\nimport os\ndef generate_summary(metrics: Dict[str, Any], intel: Dict[str, Any], risk_score: int, criticality: str, triggered_rules: List[str]) -> str:\n\n    lines: List[str] = []\n\n    lines.append(\n        'FortiGate Session Summary = Criticality: {crit}, Risk Score: {score}'\n        .format(crit=criticality, score=risk_score)\n    )\n\n    if triggered_rules:\n        lines.append('Triggered Rules: ' + ', '.join(triggered_rules))\n    else:\n        lines.append('Triggered Rules: none')\n\n    # Core metrics\n    lines.append('Metrics:')\n    lines.append(\n        '  - Events: {ec} | Allows: {ac} | Denies: {dc}'\n        .format(\n            ec=metrics.get('event_count', 0),\n            ac=metrics.get('allow_count', 0),\n            dc=metrics.get('deny_count', 0),\n        )\n    )\n\n    lines.append(\n        '  - Unique destination ports: {v}'.format(\n            v=metrics.get('unique_dest_ports', 0)\n        )\n    )\n\n    lines.append(\n        '  - Avg bytes sent: {v}'.format(\n            v=int(metrics.get('avg_bytes_sent', 0) or 0)\n        )\n    )\n\n    tags = metrics.get('threat_tags') or []\n    if tags:\n        lines.append('  - Threat tags: ' + ', '.join(tags))\n\n    # Intel\n    lines.append('Threat Intel:')\n    lines.append(\n        '  - AlienVault: malicious={mal}, suspicious={sus}'.format(\n            mal=metrics.get('malicious', 0),\n            sus=metrics.get('suspicious', 0)\n        )\n    )\n\n    country = intel.get('country') or '-'\n    bl_loc = intel.get('blacklisted_location')\n\n    geo_line = '  - GeoIP: country = {}'.format(country)\n    if bl_loc:\n        geo_line += ' (blacklisted location)'\n\n    lines.append(geo_line)\n    return os.linesep.join(lines)\n    \noutput = generate_summary(metrics, intel, risk_score, criticality, triggered_rules)",
            "variables": {
                "metrics": "step.9.output",
                "intel": "step.10.output.intel",
                "risk_score": "step.10.output.risk_score",
                "triggered_rules": "step.10.output.triggered_rules",
                "criticality": "step.11.output.criticality"
            }
        },
        "template": "{{output}}"
    } #12
]

def template():
    return """
{%- if not step_2 -%}
The investigation cannot continue because no external IP addresses were identified in the data.
{%- else -%}

{%- if not step_3 -%}
The investigation cannot advance because the IP intelligence report could not be retrieved from AlienVault.
{%- else -%}

{%- set intel = step_9.intel if step_9 and step_9.intel is not none else {} -%}
{%- set risk_score = step_9.risk_score if step_9 and step_9.risk_score is not none else 0 -%}
{%- set criticality = step_10 if step_10 else 'Unknown' -%}
{%- set triggered_rules = step_9.triggered_rules if step_9 and step_9.triggered_rules is not none else [] -%}
{%- set metrics = step_8 if step_8 else {} -%}

{%- set event_count = metrics.event_count or 0 -%}
{%- set deny_count = metrics.deny_count or 0 -%}
{%- set allow_count = metrics.allow_count or 0 -%}
{%- set unique_ports = metrics.unique_dest_ports or 0 -%}
{%- set avg_bytes = metrics.avg_bytes_sent or 0 -%}
{%- set proto = metrics.protocol or '' -%}
{%- set mal = metrics.malicious or 0 -%}
{%- set country = intel.country -%}
{%- set bl_country = intel.blacklisted_country -%}

Firewall activity included {{ event_count }} total event{{ 's' if event_count != 1 else '' }}, consisting of
{{ allow_count }} allowed connection{{ 's' if allow_count != 1 else '' }} and
{{ deny_count }} denied connection{{ 's' if deny_count != 1 else '' }}.
Traffic spanned {{ unique_ports }} unique destination port{{ 's' if unique_ports != 1 else '' }}.
{%- if avg_bytes and avg_bytes > 0 %}
The average data volume per event was approximately {{ avg_bytes | int }} bytes.
{%- endif %}

{%- if country %}
The external IP address resolved to a geolocation in {{ country }}.
{%- if bl_country %}
 This location is classified as a restricted or blacklisted region.
{%- endif %}
{%- endif %}

{%- if triggered_rules|length == 0 -%}
No behavioral rules related to scanning, data exfiltration, or malicious communication were triggered during this session.
{%- else -%}
The analysis identified {{ triggered_rules|length }} notable pattern{{ 's' if triggered_rules|length != 1 else '' }}:
{{ triggered_rules | join('; ') }}.
{%- endif %}

Based on the combined firewall behavior, threat intelligence context, and rule evaluation,
the session received a cumulative risk score of {{ risk_score }} and is classified as
<b>{{ criticality }}</b>.

{%- if criticality == 'Ignore' %}
The observed activity aligns with expected network behavior and does not currently indicate a security threat.
{%- elif criticality == 'Medium' %}
The observed activity shows potentially unusual behavior and should be monitored for recurrence or escalation.
{%- elif criticality == 'High' %}
The observed activity demonstrates high-risk indicators and requires immediate investigation and response.
{%- endif %}

{%- endif -%}
{%- endif -%}
"""
