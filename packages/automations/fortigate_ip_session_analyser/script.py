
def steps():
    return [
    {
        "name": "extract",
        "parameters": {
            "step": 0,
            "path": "source_ip"
        },
        "template": "Extracted source IP: {{ output if output else 'No IP found' }}.",
        "artifacts": [
            "{{output}}"
        ]
    },
    {
        "name": "extract",
        "parameters": {
            "step": 0,
            "path": "[\"source_ip.set\"]"
        },
        "template": "Extracted source IP: {{ output if output else 'No IP found' }}.",
        "artifacts": [
            "{{output[0]}}"
        ]
    },
    {
        "name": "extract",
        "parameters": {
            "step": 0,
            "path": "destination_ip"
        },
        "template": "Extracted destination IP: {{ output if output else 'No IP found' }}.",
        "artifacts": [
            "{{output}}"
        ]
    },
    {
        "name": "extract",
        "parameters": {
            "step": 0,
            "path": "[\"destination_ip.set\"]"
        },
        "template": "Extracted destination IP: {{ output if output else 'No IP found' }}.",
        "artifacts": [
            "{{output[0]}}"
        ]
    },
    {
        "name": "extract",
        "parameters": {
            "step": 0,
            "path": "source_remote_ip"
        },
        "template": "Extracted source remote IP: {{ output if output else 'No IP found' }}.",
        "artifacts": [
            "{{output}}"
        ]
    },
    {
        "name": "execute_python",
        "parameters": {
            "code": "import ipaddress\n\ndef is_internal_ip(ip_str: str) -> bool:\n    try:\n        if not ip_str:\n            ip = ipaddress.ip_address(ip_str)\n            return ip.is_private or ip.is_loopback or ip.is_link_local\n    except ValueError:\n        return False\n\ndef is_external_ip(ip_str: str) -> bool:\n    return not is_internal_ip(ip_str)\n\ndef find_external_ip(source_ip:str ,destination_ip:str, source_ip_set,destination_ip_set,source_remote_ip) :\n    external_ips = []\n    if is_external_ip(source_remote_ip):\n        external_ips.append(source_remote_ip)\n    if is_external_ip(source_ip):\n        external_ips.append(source_ip)\n    if is_external_ip(destination_ip):\n        external_ips.append(destination_ip)\n    if source_ip_set:\n        for ip in source_ip_set:\n            if is_external_ip(ip):\n                external_ips.append(ip)\n    if destination_ip_set:\n        for ip in destination_ip_set:\n            if is_external_ip(ip):\n                external_ips.append(ip)\n\n    return list({ip for ip in external_ips if ip})\n\noutput = find_external_ip(source_ip,destination_ip,source_ip_set,destination_ip_set, source_remote_ip)\n\n\n",
            "variables": {
                "source_ip": "step.1.output",
                "destination_ip": "step.3.output",
                "source_ip_set": "step.2.output[0]",
                "destination_ip_set": "step.4.output[0]",
                "source_remote_ip":"step.5.output"
            }
        },
        "template": "{%- if output is none -%}\nNo any external IP address was found for analysis.\n{%- else -%}\nThe IP address {{ output }} are external ip addresses.\n{%- endif -%}"
    },
    {
        "name": "evaluate",
        "parameters": {
            "step": 6,
            "condition": "output is not None",
            "if_step": 8,
            "else_step": 20
        },
        "template": "{{ 'External IP detected, so the process moves to step 5 for further analysis.' if output else 'As no any external IP Address detected, the process stops here.' }}"
    },
    {
        "name": "action",
        "parameters": {
            "action": "AlienVault",
            "fields": {
                "client.ip": {
                    "step": 6,
                    "path": "output"
                }
            }
        },
        "template": "{%- if output and output.responses -%}\nAlienVault analysis finished.\n{% for ip, resp in output.responses.items() -%}\n{%- set stats = resp.pulse_info.count if resp and resp.pulse_info else {}-%}\n{{ ip }} - Malicious: {{ stats }}\n{% endfor -%}\n{% else -%}\nNo AlienVault data available.\n{% endif %}"
    },
    {
        "name": "action",
        "parameters": {
            "action": "LookupIpv4",
            "fields": {
                "ipaddress": {
                    "step": 6,
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
    },
    {
        "name": "action",
        "parameters": {
            "action": "BlacklistedCountries",
            "fields": {
                "country": {
                    "step": 9,
                    "path": "output.responses.*.rows[0][5]"
                }
            }
        },
        "template": "{%- set ns = namespace(blacklisted=[], all_locations=[]) -%}\n\n{%- for country, data in output.responses.items() -%}\n    {%- set ns.all_locations = ns.all_locations + [country] -%}\n    {%- if data.rows | length > 0 -%}\n        {%- set ns.blacklisted = ns.blacklisted + [country] -%}\n    {%- endif -%}\n{%- endfor %}\n\n{%- if ns.blacklisted | length > 0 -%}\nThe geolocation ({{ ns.blacklisted | join(', ') }}) extracted from an IP address above is BLACKLISTED.\n{%- else -%}\nThe geolocation ({{ ns.all_locations | join(', ') }}) extracted from an IP address above is not blacklisted.\n{%- endif %}"
    },
      
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
    },
    {
        "name": "execute_python",
        "parameters": {
            "code": "import shlex\nfrom datetime import datetime\nfrom typing import Any, Dict, List, Optional\n\ndef _parse_time(ts: Any) -> Optional[datetime]:\n    if ts is None:\n        return None\n    if isinstance(ts, datetime):\n        return ts\n    # Try common FortiGate formats (ISO8601 or epoch seconds)\n    try:\n        if isinstance(ts, (int, float)):\n            return datetime.utcfromtimestamp(float(ts))\n        # Attempt ISO parsing\n        return datetime.fromisoformat(str(ts).replace('Z', '+00:00'))\n    except Exception:\n        return None\n\ndef _parse_fortigate_kv_message(message: str) -> Dict[str, Any]:\n    data: Dict[str, Any] = {}\n    try:\n        tokens = shlex.split(message)\n    except Exception:\n        tokens = message.split()\n    for tok in tokens:\n        if '=' not in tok:\n            continue\n        k, v = tok.split('=', 1)\n        # Trim surrounding quotes if any\n        if len(v) >= 2 and ((v[0] == '\"' and v[-1] == '\"') or (v[0] == \"'\" and v[-1] == \"'\")):\n            v = v[1:-1]\n        # Cast obvious ints\n        if v.isdigit():\n            try:\n                data[k] = int(v)\n                continue\n            except Exception:\n                pass\n        # Cast floats for large epoch-like numbers (keep as str if fails)\n        try:\n            if '.' in v and v.replace('.', '', 1).isdigit():\n                data[k] = float(v)\n                continue\n        except Exception:\n            pass\n        data[k] = v\n    return data\n\ndef _normalize_fortigate_event(e: Dict[str, Any]) -> Optional[Dict[str, Any]]:\n    # If already normalized (heuristic)\n    if any(k in e for k in ('src_ip', 'dst_ip', 'dst_port', 'protocol')) and 'message' not in e:\n        return e\n\n    msg = e.get('message')\n    if not isinstance(msg, str):\n        return e if isinstance(e, dict) else None\n\n    # Quick check for FortiGate kv format\n    if 'srcip=' in msg and 'dstip=' in msg:\n        kv = _parse_fortigate_kv_message(msg)\n\n        # Time resolution: prefer eventtime (often ns) else date+time (+ tz)\n        ts: Optional[datetime] = None\n        eventtime = kv.get('eventtime')\n        if isinstance(eventtime, (int, float)):\n            # Many FortiGate logs use nanoseconds; fall back to seconds if small\n            try:\n                ts_val = float(eventtime)\n                # Heuristic: if ts looks like nanoseconds (>= 1e12), convert\n                if ts_val > 1e12:\n                    ts = datetime.utcfromtimestamp(ts_val / 1_000_000_000)\n                else:\n                    ts = datetime.utcfromtimestamp(ts_val)\n            except Exception:\n                ts = None\n        if ts is None:\n            dt_str = ''+kv.get('date','')+' '+ kv.get('time','')\n            ts = _parse_time(dt_str)\n\n        # Protocol mapping\n        proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}\n        proto_val = kv.get('proto')\n        protocol = None\n        try:\n            if isinstance(proto_val, str) and proto_val.isdigit():\n                proto_val = int(proto_val)\n            protocol = proto_map.get(proto_val, str(proto_val) if proto_val is not None else None)\n        except Exception:\n            protocol = None\n\n        # Action mapping\n        raw_action = str(kv.get('action', e.get('action', ''))).lower()\n        action_map = {\n            'accept': 'ALLOW',\n            'close': 'ALLOW',\n            'pass': 'ALLOW',\n            'blocked': 'DENY',\n            'deny': 'DENY',\n            'block': 'DENY',\n            'client-rst': 'ALLOW',\n            'server-rst': 'ALLOW',\n        }\n        action = action_map.get(raw_action, raw_action.upper() if raw_action else None)\n\n        # Bytes: we use sentbyte as our 'bytes' metric (as per module docstring)\n        bytes_val = kv.get('sentbyte')\n        try:\n            bytes_val = float(bytes_val) if bytes_val is not None else 0\n        except Exception:\n            bytes_val = 0\n\n        norm: Dict[str, Any] = {\n            'time': ts.isoformat() if isinstance(ts, datetime) else None,\n            'action': action,\n            'src_ip': kv.get('srcip'),\n            'dst_ip': kv.get('dstip'),\n            'src_port': kv.get('srcport'),\n            'dst_port': kv.get('dstport'),\n            'protocol': protocol,\n            'bytes': bytes_val,\n            'policy_id': kv.get('policyid'),\n            'policy_name': kv.get('policyname'),\n            'device_name': kv.get('devname'),\n            'service': kv.get('service') or kv.get('app'),\n        }\n        # Optional enrichment from kv\n        threat_tags: List[str] = []\n        apprisk = str(kv.get('apprisk', '')).lower()\n        if apprisk in {'elevated', 'high', 'critical'}:\n            threat_tags.append('elevated_risk_app')\n        if str(kv.get('logid', '')).startswith('0316') and action == 'DENY':\n            threat_tags.append('webfilter_block')\n        if threat_tags:\n            norm['threat_tags'] = threat_tags\n\n        return norm\n\n    # Fallback: if message looks like JSON we might extend here later; for now return original\n    return e\n\ndef _preprocess_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:\n    normalized: List[Dict[str, Any]] = []\n    for e in events or []:\n        try:\n            if e.get('provider') == 'Fortigate':\n                n = _normalize_fortigate_event(e)\n                if n is not None:\n                    normalized.append(n)\n        except Exception:\n            # Best-effort: skip bad event\n            continue\n    return normalized\n\noutput = _preprocess_events(session)",
            "variables": {
                "session": "step.11.output.result"
            }
        },
        "template": "This step parsed and normalized raw FortiGate firewall logs into structured JSON data. It extracted essential fields such as source and destination IPs, ports, protocols, actions, timestamps, and policy details while omitting redundant attributes. The logs were converted from FortiGate’s key–value format into clean dictionaries, with timestamps accurately interpreted and protocol or action codes mapped to readable values. Additional contextual tags like elevated risk or web filter blocks were added, resulting in a uniform, enriched dataset ready for downstream analysis."
    },
    {
        "name": "execute_python",
        "parameters": {
            "code": "from statistics import mean\nfrom typing import Any, Dict, List\n\ndef _safe_mean(values: List[float]) -> float:\n    return mean(values) if values else 0.0\n\ndef aggregate_threatintel(ipreports: Dict[str, Any]) -> Dict[str, Any]:\n    malicious = 0\n    for ip, report in ipreports.items():\n        try:\n            if report.get('pulse_info').get('count') > 0:\n                malicious += report.get('pulse_info').get('count')\n        except Exception as e:\n            pass\n    return malicious\n    \n\ndef aggregate_metrics(events: List[Dict[str, Any]], ipreports: Dict[str, Any]) -> Dict[str, Any]:\n    return {\n        'event_count': len(events),\n        'deny_count': sum(1 for e in events if str(e.get('action', '')).upper() == 'DENY'),\n        'allow_count': sum(1 for e in events if str(e.get('action', '')).upper() == 'ALLOW'),\n        'unique_dest_ports': len({e.get('dst_port') for e in events if e.get('dst_port') is not None}),\n        'avg_bytes_sent': _safe_mean([float(e.get('bytes', 0) or 0) for e in events]) if events else 0.0,\n        'threat_tags': list({t for e in events for t in (e.get('threat_tags') or [])}),\n        'protocol': events[0].get('protocol') if events else None,\n        'malicious': aggregate_threatintel(ipreports)\n    }\noutput = aggregate_metrics(events, ipreports)\n\n\n",
            "variables": {
                "events": "step.12.output",
                "ipreports": "step.8.output.responses"
            }
        },
        "template": "{%- if not output -%}\nNo security-relevant events were identified during the analysis window.\n{%- else -%}\nA total of {{ output.event_count }} network events were observed during the analysis period. \nOf these, {{ output.allow_count }} events were permitted and {{ output.deny_count }} were blocked by the security controls.\n{%- if output.protocol %}\n The predominant protocol identified across the events was {{ output.protocol }}.\n{%- endif %}\n Traffic was recorded across {{ output.unique_dest_ports }} distinct destination ports, indicating the breadth of service interaction.\n{%- if output.avg_bytes_sent and output.avg_bytes_sent > 0 %}\n The average data transfer volume per event was approximately {{ \"%.2f\"|format(output.avg_bytes_sent) }} bytes.\n{%- endif %}\n{%- if output.threat_tags and output.threat_tags|length > 0 %}\n Threat intelligence mapping associated the activity with the following indicators or classifications: {{ output.threat_tags | sort | join(', ') }}.\n{%- else %}\n No threat intelligence indicators were associated with the observed events.\n{%- endif %}\n{%- endif -%}"
    },
    {
        "name": "execute_python",
        "parameters": {
            "code": "from typing import Any, Dict, List\n\nWEIGHTS = {\n    'rule_port_scan': 30,\n    'rule_ip_malicious': 30,\n    'rule_blacklisted_country': 25,\n    'rule_data_exfil': 30,\n    'rule_fw_tag_malicious': 35,\n    'rule_high_risk_port_allow': 20,\n    'rule_high_deny_ratio': 10,\n    'rule_beacon_like': 15,\n}\n\ndef apply_rules(metrics: Dict[str, Any], intel: Dict[str, Any]) -> Dict[str, Any]:\n\n    risk_score = 0\n    triggered_rules: List[str] = []\n\n    deny_ratio = (metrics.get('deny_count', 0)/metrics.get('event_count', 0))*100\n    # 1. Port scan detection (baseline)\n    if deny_ratio > 50 and metrics.get('unique_dest_ports', 0) > 20:\n        triggered_rules.append('Port Scan Detected')\n        risk_score += WEIGHTS['rule_port_scan']\n\n    # 2. Outbound malicious connection (IP Report)\n    if metrics.get('malicious', 0) > 0:\n        triggered_rules.append('Destination marked malicious in Report')\n        risk_score += WEIGHTS['rule_ip_malicious']\n\n    # 4. Blacklisted location (GeoIP)\n    if intel.get('blacklisted_country'):\n        country = intel.get('blacklisted_country')\n        triggered_rules.append(f'Destination in blacklisted country {country}')\n        risk_score += WEIGHTS['rule_blacklisted_country']\n\n    # 5. High data exfiltration\n    if metrics.get('avg_bytes_sent', 0) > 1_000_000:\n        triggered_rules.append('Possible data exfiltration')\n        risk_score += WEIGHTS['rule_data_exfil']\n\n    # 6. Threat tags from firewall logs\n    if any(tag in {'c2', 'malware', 'phishing'} for tag in metrics.get('threat_tags', [])):\n        triggered_rules.append('Firewall tag indicates malicious activity')\n        risk_score += WEIGHTS['rule_fw_tag_malicious']\n\n    return {'risk_score': risk_score, 'triggered_rules': triggered_rules, 'intel':intel}\n\n\noutput = apply_rules(metrics, {'blacklisted_country': blacklisted_country[0] if blacklisted_country else None})",
            "variables": {
                "metrics": "step.13.output",
                "blacklisted_country": "step.10.output.responses.*.rows[0]"
            }
        },
        "template": "{%- set triggered_rules = output.triggered_rules or [] -%}\n{%- set intel = output.intel or {} -%}\n{%- set risk_score = output.risk_score or 0 -%}\n\n{%- if triggered_rules|length == 0 -%}\nThe analyzed network activity shows no indications of scanning behavior, data exfiltration, or malicious communication attempts. No threat intelligence or firewall alerts were triggered during this observation period.\n{%- else -%}\nThe analysis identified {{ triggered_rules|length }} notable event(s): {{ triggered_rules | join('; ') }}.\n{%- if intel.malicious and intel.malicious > 0 -%}\nThreat intelligence reports indicate {{ intel.malicious }} destination(s) classified as malicious by VirusTotal.\n{%- endif -%}\n{%- if intel.blacklisted_country -%}\nOne or more destinations are located in a restricted geography, identified as {{ intel.blacklisted_country }}.\n{%- endif -%}\nThe computed cumulative risk score from triggered indicators is {{ risk_score }}, reflecting the combined impact of observed behaviors.\n{%- endif -%}"
    },
    {
        "name": "execute_python",
        "parameters": {
            "code": "from typing import Dict\n\nCRIT_THRESHOLDS = {\n    'ignore': 30,  \n    'medium': 60,\n}\n\ndef determine_criticality(risk_score: int, metrics: Dict[str, Any], intel: Dict[str, Any]) -> str:\n    # Base on risk score thresholds\n    if risk_score < CRIT_THRESHOLDS['ignore']:\n        criticality = 'Ignore'\n    elif risk_score < CRIT_THRESHOLDS['medium']:\n        criticality = 'Medium'\n    else:\n        criticality = 'High'\n\n    # Escalation rules: malicious VT or blacklisted location/IP → at least Medium/High\n    if metrics.get('malicious', 0) > 0 or intel.get('blacklisted_location') or intel.get('blacklisted_ip'):\n        criticality = 'High' if risk_score >= 50 else max(criticality, 'Medium', key=lambda x: ['Ignore', 'Medium', 'High'].index(x))\n\n    return criticality\noutput = determine_criticality(risk_score, metrics, intel)",
            "variables": {
                "metrics": "step.13.output",
                "intel": "step.14.output.intel",
                "risk_score": "step.14.output.risk_score"
            }
        },
        "template": "{%- set criticality = output or 'Unknown' -%}\n\n{%- if criticality == 'Ignore' -%}\nThe analyzed event is classified as low priority, indicating minimal risk and no immediate signs of malicious or suspicious behavior.\n{%- elif criticality == 'Medium' -%}\nThe analyzed event is classified as medium priority, suggesting potentially unusual or noteworthy activity that warrants further observation.\n{%- elif criticality == 'High' -%}\nThe analyzed event is classified as high priority, indicating strong evidence of risky or malicious behavior requiring prompt review.\n{%- else -%}\nThe criticality level of the analyzed event could not be determined due to insufficient data.\n{%- endif -%}"
    },
    {
        "name": "execute_python",
        "parameters": {
            "code": "from typing import Any, Dict, List\nimport os\ndef generate_summary(source_ip:str, external_ips:List[str] ,metrics: Dict[str, Any], intel: Dict[str, Any], risk_score: int, criticality: str, triggered_rules: List[str]) -> str:\n\n    lines: List[str] = []\n\n    lines.append(\n        'FortiGate Session Summary = Criticality: {crit}, Risk Score: {score}'\n        .format(crit=criticality, score=risk_score)\n    )\n\n    if triggered_rules:\n        lines.append('Triggered Rules: ' + ', '.join(triggered_rules))\n    else:\n        lines.append('Triggered Rules: none')\n\n    # Core metrics\n    lines.append('Metrics:')\n    lines.append(\n        '  - Events: {ec} | Allows: {ac} | Denies: {dc}'\n        .format(\n            ec=metrics.get('event_count', 0),\n            ac=metrics.get('allow_count', 0),\n            dc=metrics.get('deny_count', 0),\n        )\n    )\n\n    lines.append(\n        '  - Unique destination ports: {v}'.format(\n            v=metrics.get('unique_dest_ports', 0)\n        )\n    )\n\n    lines.append(\n        '  - Avg bytes sent: {v}'.format(\n            v=int(metrics.get('avg_bytes_sent', 0) or 0)\n        )\n    )\n\n    if source_ip is not None and external_ips is not None and source_ip in external_ips:\n        external_ips.remove(source_ip)\n    proto = metrics.get('protocol') or '-'\n\n    if source_ip is not None:\n        lines.append(\n            '  - Flow: {s} -> {d} ({p})'.format(s=source_ip, d=external_ips, p=proto)\n        )\n\n    tags = metrics.get('threat_tags') or []\n    if tags:\n        lines.append('  - Threat tags: ' + ', '.join(tags))\n\n    # Intel\n    lines.append('Threat Intel:')\n    lines.append(\n        '  - AlienVault: malicious={mal}, suspicious={sus}'.format(\n            mal=metrics.get('malicious', 0),\n            sus=metrics.get('suspicious', 0)\n        )\n    )\n\n    country = intel.get('country') or '-'\n    bl_loc = intel.get('blacklisted_location')\n\n    geo_line = '  - GeoIP: country = {}'.format(country)\n    if bl_loc:\n        geo_line += ' (blacklisted location)'\n\n    lines.append(geo_line)\n    return os.linesep.join(lines)\n    \noutput = generate_summary(source_ip, external_ips, metrics, intel, risk_score, criticality, triggered_rules)",
            "variables": {
                "metrics": "step.13.output",
                "intel": "step.14.output.intel",
                "risk_score": "step.14.output.risk_score",
                "triggered_rules": "step.14.output.triggered_rules",
                "criticality": "step.15.output.criticality",
                "source_ip":"step.1.output",
                "external_ips":"step.6.output"
            }
        },
        "template": "{{output}}"
    }
]

def template():
    return """
{%- if not step_6 -%}
The investigation cannot continue because no external IP addresses were identified in the data.
{%- else -%}

{%- if not step_7 -%}
The investigation cannot advance because the IP intelligence report could not be retrieved from AlienVault.
{%- else -%}

{%- set intel = step_13.intel if step_13 and step_13.intel is not none else {} -%}
{%- set risk_score = step_13.risk_score if step_13 and step_13.risk_score is not none else {} -%}
{%- set criticality = step_14 if step_14 else 'Unknown' -%}
{%- set triggered_rules = step_13.triggered_rules if step_13 and step_13.triggered_rules is not none else [] -%}
{%- set metrics = step_12 if step_12 else {} -%}
{%- set event_count = metrics.event_count or 0 -%}
{%- set deny_count = metrics.deny_count or 0 -%}
{%- set allow_count = metrics.allow_count or 0 -%}
{%- set unique_ports = metrics.unique_dest_ports or 0 -%}
{%- set avg_bytes = metrics.avg_bytes_sent or 0 -%}
{%- set src_ip = step_0 or step_1[0] -%}
{%- set dst_ip = step_2 or step_3[0] -%}
{%- set proto = metrics.protocol or '' -%}
{%- set tags = metrics.threat_tags or [] -%}
{%- set mal = metrics.malicious or 0 -%}
{%- set susp = metrics.suspicious or 0 -%}
{%- set bl_country = intel.blacklisted_country -%}

{%- set ip_context_notes = [] -%}
{%- for ip, data in step_7.responses.items() -%}
    {%- if data.pulse_info and data.pulse_info['count'] > 0 -%}
        {%- set note =
            "The IP address " ~ ip ~
            " is known malicious, carrying a threat score of " ~
            data.pulse_info['count'] ~
            ", reinforcing that this is likely part of an automated reconnaissance or credential-harvesting attempt."
        -%}
        {%- set _ = ip_context_notes.append(note) -%}
    {%- endif -%}
{%- endfor -%}


{# Build the IP text dynamically #}
{%- if src_ip and dst_ip -%}
    {%- set ip_text = src_ip ~ ' and ' ~ dst_ip -%}
{%- elif src_ip -%}
    {%- set ip_text = src_ip -%}
{%- elif dst_ip -%}
    {%- set ip_text = dst_ip -%}
{%- else -%}
    {%- set ip_text = '' -%}
{%- endif -%}

{%- if triggered_rules|length == 0 -%}
The session{% if ip_text %} between {{ ip_text }}{% endif %} ({{ proto }}) exhibited no indicators of malicious or policy-violating activity.
{%- if avg_bytes and avg_bytes > 100 -%}
Average data transfer volume was {{ avg_bytes | int }} bytes.
{%- endif -%}
The overall risk assessment yields a score of {{ risk_score }}, classified as <b>{{ criticality }}</b>, indicating stable network behavior with no significant threats detected.
{%- else -%}
Analysis of network activity{% if ip_text %} from {{ ip_text }}{% endif %}{% if proto %} ({{ proto }}){% endif %} revealed {{ triggered_rules|length }} notable pattern(s): <b>{{ triggered_rules | join('; ') }}</b>.\n
{%- if ip_context_notes -%}
    {%- for note in ip_context_notes -%}
{{ note }}
    {%- endfor -%}
{%- endif -%}
{%- if bl_country %}, Threat intelligence report also includes traffic linked to blacklisted geography {{ bl_country }}{%- endif %}. The cumulative risk score of <b>{{ risk_score }}</b> classifies this session as <b>{{ criticality }}</b>, reflecting {{ 'high-confidence malicious or policy-violating behavior' if criticality == 'High' else ('potentially risky or unusual activity requiring further validation' if criticality == 'Medium' else 'low-level anomalous activity without strong threat indicators') }}.
{%- endif -%}

{%- endif -%}

{%- endif -%}
"""

# {%- set ip_context_notes = [] %}
# {%- for ip, data in step_7.responses.items() %}
#     {%- if data.pulse_info and data.pulse_info.count > 0 %}

#         {%- set note = 
#             "The IP address " ~ ip 
#             ~ " is known malicious, carrying a threat score of " 
#             ~ data.pulse_info.count 
#             ~ ", reinforcing that this is likely part of an automated reconnaissance or credential-harvesting attempt."
#         %}
#         {%- set _ = ip_context_notes.append(note) %}

#     {%- endif %}
# {%- endfor %}

# {-% if ip_context_notes -%}
# {% for note in ip_context_notes %}
# {{ note }}
# {% endfor %}
# {% endif %}