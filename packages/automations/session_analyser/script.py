def steps():
  
    return [
        {
            "name": "action",
            "parameters": {
                "action": "EventSession",
                "step":0,
                "path":"@"
            },
            "template": "The log details a series of network security events captured by the FortiGate firewall, showing repeated activity associated with a common source or destination. The close sequence of timestamps indicates these events occurred in rapid succession, suggesting a brief burst of network traffic or automated session activity. This pattern may reflect user-driven access, policy enforcement, or a batch of connections initiated within a short monitoring window."
        }, 
        {
            "name": "execute_python",
            "parameters": {
                "code": """
def analyze_identity(artifacts):
    actions = artifacts.get("event_action", [])
    failure_reasons = artifacts.get("failure_reason", [])
    
    signals = []
    
    # Excessive login failures
    fail_count = actions.count("ssl-login-fail") + actions.count("login failed")
    if fail_count >= 3:
        signals.append("excessive_login_failures")

    # Login success after failures
    has_success = "login successfully" in actions or "tunnel-up" in actions
    if fail_count > 0 and has_success:
        signals.append("login_success_after_failures")
    
    # MFA Checks
    if "mfa_failed" in actions or "mfa_challenge_fail" in failure_reasons:
        signals.append("mfa_failure")
         
    return {
        "signals": signals,
        "verdict": "REVIEW" if signals else "IGNORE"
    }

output = analyze_identity(artifacts)
""",
                "variables": {
                    "artifacts": "step.0.siem_analysis.artifacts"
                }
            },
            "template": "Identity and authentication analysis is complete with a verdict of <b>{{ output.verdict }}</b>. The session was evaluated for authentication failures, login success following failures, MFA challenge and failure conditions, and abnormal authentication sequences. {% if output.signals %}The analysis identified the following identity-related anomalies: {{ output.signals | join(', ') | replace('_', ' ') }}, which may indicate authentication abuse or account compromise attempts.{% else %}No abnormal authentication patterns were detected, and user login behavior remained consistent with expected norms.{% endif %}",
          "artifacts":["Identity and Authentication"]
        },
        {
            "name": "execute_python",
            "parameters": {
                "code": """
def analyze_endpoint(artifacts):
    edr_actions = artifacts.get("edr_action", [])
    edr_severities = artifacts.get("edr_severity", [])
    tamper_status = artifacts.get("tamper_status", [])
    
    signals = []
    
    if any(a in ["blocked", "killed", "quarantined", "cleaned"] for a in edr_actions):
        signals.append("edr_prevention_action")

    if any(s.lower() in ["high", "critical"] for s in edr_severities):
        signals.append("high_severity_edr_alert")

    if "disabled" in tamper_status or "prevention_disabled" in edr_actions:
         signals.append("prevention_tampered_or_disabled")

    verdict = "IGNORE"
    if "edr_prevention_action" in signals:
        verdict = "ESCALATE"
    elif signals:
        verdict = "REVIEW"

    return {
        "signals": signals,
        "verdict": verdict
    }

output = analyze_endpoint(artifacts)
""",
                "variables": {
                    "artifacts": "step.0.siem_analysis.artifacts"
                }
            },
            "template": "Endpoint posture and EDR health analysis completed with a verdict of {{ output.verdict }}. The evaluation covered endpoint protection actions, EDR alert severity levels, prevention or tamper status, and overall endpoint defense integrity. {% if output.signals %}The analysis revealed endpoint security concerns including {{ output.signals | join(', ') | replace('_', ' ') }}, suggesting possible endpoint compromise or weakened defenses.{% else %}No high-severity EDR alerts, tampering indicators, or prevention failures were observed, and endpoint protections appear to be functioning as expected.{% endif %}"
        },
        {
            "name": "execute_python",
            "parameters": {
                "code": """
def analyze_process(artifacts):
    lolbins = {"powershell", "cmd.exe", "bash", "curl", "wget", "python", "rundll32", "mshta", "regsvr32", "wmic"}
    processes = artifacts.get("process_name", [])
    signed_statuses = artifacts.get("signed_status", [])
    
    signals = []
    
    for p in processes:
        if p.lower() in lolbins:
            signals.append(f"lolbin_execution:{p}")

    if "unsigned" in signed_statuses:
        signals.append("unsigned_binary_execution")

    return {
        "signals": signals,
        "verdict": "REVIEW" if signals else "IGNORE"
    }

output = analyze_process(artifacts)
""",
                "variables": {
                    "artifacts": "step.0.siem_analysis.artifacts"
                }
            },
            "template": "Process execution analysis completed with a verdict of {{ output.verdict }}. The session was reviewed for known LOLBin usage, execution of unsigned binaries, and potentially suspicious process behavior. {% if output.signals %}Suspicious process execution indicators were detected, including {{ output.signals | join(', ') | replace('_', ' ') }}, which may indicate living-off-the-land or malicious execution techniques.{% else %}No suspicious process executions, LOLBin abuse, or unsigned binary activity were observed during the session.{% endif %}"
        },
        {
            "name": "execute_python",
            "parameters": {
                "code": """
def analyze_file(artifacts):
    file_paths = artifacts.get("file_path", [])
    operations = artifacts.get("operation", [])
    sensitivity = artifacts.get("sensitivity_label", []) 
    
    signals = []
    
    if any(label in ["confidential", "secret", "high"] for label in sensitivity):
        signals.append("sensitive_data_access")

    system_paths = ["/etc/", "c:\\\\windows\\\\system32", "/startup"]
    for path in file_paths:
        if any(sys_path in path.lower() for sys_path in system_paths) and "write" in operations:
            signals.append("write_to_system_path")
    
    if operations.count("rename") > 5 or operations.count("delete") > 10:
        signals.append("high_volume_file_modification")
         
    return {
        "signals": signals,
        "verdict": "REVIEW" if signals else "IGNORE"
    }

output = analyze_file(artifacts)
""",
                "variables": {
                    "artifacts": "step.0.siem_analysis.artifacts"
                }
            },
            "template": "File operation analysis concluded with a verdict of {{ output.verdict }}. The session was examined for access to sensitive files, write activity in system or startup paths, and high-volume file modification behavior. {% if output.signals %}File-related anomalies were detected, including {{ output.signals | join(', ') | replace('_', ' ') }}, which may indicate persistence attempts or data staging activity.{% else %}File access and modification patterns remained within normal operational boundaries with no indicators of malicious behavior.{% endif %}"
        },
        {
            "name": "execute_python",
            "parameters": {
                "code": """
def extract_file_hash(artifacts,event):
    file_hashes = set()
    for key,value in artifacts.items() :
        if "hash" in key :
            if isinstance(value, list):
                file_hashes.update(value)
            elif isinstance(value, str):
                file_hashes.add(value)

    for key,value in event.items() :
        if "hash" in key :
            if isinstance(value, list):
                file_hashes.update(value)
            elif isinstance(value, str):
                file_hashes.add(value)
    
    return list(file_hashes) if file_hashes else None

output = extract_file_hash(artifacts,event)
""",
                "variables": {
                    "artifacts": "step.0.siem_analysis.artifacts",
                    "event":"step.0.@"
                }
            },
            "template": "File Hash extracted from the sessions are {{output}}"
        },
        {
            "name": "evaluate",
            "parameters": {
                "step": 6,
                "condition": "output is not None",
                "if_step": 8,
                "else_step": 12
            },
            "template": "{{ 'File Hash found in session, so the process moves to further analysis of this file hash.' if output else 'As no any file hash found, the process moves to step 12.' }}"
        },
        {
            "name": "action",
            "parameters": {
                "action": "Virustotal File Analyser",
                "fields": {
                    "file_hash": {
                        "step": 6,
                        "path": "output"
                    }
                }
            },
            "template": "VirusTotal analysis finished. Malicious detections: {{ output.data.attributes.last_analysis_stats.malicious if output and output.data else 0 }}, Suspicious detections: {{ output.data.attributes.last_analysis_stats.suspicious if output and output.data else 0 }}."
        },
        {
            "name": "execute_python",
            "parameters": {
                "code": """
def extract_ipaddress(artifacts,event):
    ip_addresses = set()
    for key,value in artifacts.items() :
        if "ip" in key :
            if isinstance(value, list):
                ip_addresses.update(value)
            elif isinstance(value, str):
                ip_addresses.add(value)

    for key,value in event.items() :
        if "ip" in key :
            if isinstance(value, list):
                ip_addresses.update(value)
            elif isinstance(value, str):
                ip_addresses.add(value)
    
    return list(ip_addresses) if ip_addresses else None

output = extract_ipaddress(artifacts,event)
""",
                "variables": {
                    "artifacts": "step.0.siem_analysis.artifacts",
                    "event":"step.0.@"
                }
            },
            "template": "IP addresses extracted from the sessions are {{output}}"
        },
        {
            "name": "evaluate",
            "parameters": {
                "step": 9,
                "condition": "output is not None",
                "if_step": 11,
                "else_step": 12
            },
            "template": "{{ 'IP Addresses found in session, so the process moves to further analysis of this ipaddress.' if output else 'As no any ip address found, the process moves to step 12.' }}"
        },
        {
            "name": "action",
            "parameters": {
                "action": "Virustotal",
                "fields": {
                    "client.ip": {
                        "step": 9,
                        "path": "output"
                    }
                }
            },
            "template": "VirusTotal analysis finished. Malicious detections: {{ output.data.attributes.last_analysis_stats.malicious if output and output.data else 0 }}, Suspicious detections: {{ output.data.attributes.last_analysis_stats.suspicious if output and output.data else 0 }}."
        },
        {
            "name": "execute_python",
            "parameters": {
                "code": """
def analyze_network(artifacts):
    actions = artifacts.get("event_action", [])
    dst_ports = artifacts.get("destination_port", [])
    
    signals = []
    
    if actions.count("client-rst") + actions.count("server-rst") >= 5:
        signals.append("repeated_connection_resets")

    common_ports = {80, 443, 53, 8080, 22, 25}
    unusual_ports = [p for p in dst_ports if p not in common_ports]
    if len(unusual_ports) > 3:
        signals.append("connections_to_unusual_ports")
         
    return {
        "signals": signals,
        "verdict": "REVIEW" if signals else "IGNORE"
    }

output = analyze_network(artifacts)
""",
                "variables": {
                    "artifacts": "step.0.siem_analysis.artifacts"
                }
            },
            "template": "Network connection analysis completed with a verdict of {{ output.verdict }}. The session was evaluated for repeated connection resets and connections to unusual destination ports. {% if output.signals %}Abnormal network behavior was identified, including {{ output.signals | join(', ') | replace('_', ' ') }}, which may indicate scanning activity or unstable command-and-control behavior.{% else %}Network connection patterns appeared normal, with no excessive resets or suspicious port usage observed.{% endif %}"
        },
        {
            "name": "execute_python",
            "parameters": {
                "code": """
def analyze_traffic(artifacts):
    out_bytes = sum(artifacts.get("network_bytes_out_total", [0]))
    in_bytes = sum(artifacts.get("network_bytes_in_total", [0]))
    tunnel_types = artifacts.get("tunnel_type", [])
    actions = artifacts.get("event_action", [])

    signals = []

    if out_bytes > 1_000_000 and (in_bytes == 0 or out_bytes > in_bytes * 5):
        signals.append("potential_exfiltration_high_outbound")

    if "dns" in tunnel_types or "ssh" in tunnel_types:
         signals.append("potential_tunneling")
    if "tunnel-down" in actions and "tunnel-up" in actions:
         signals.append("VPN_tunnel_instability")
         
    return {
        "signals": signals,
        "verdict": "ESCALATE" if signals else "IGNORE"
    }

output = analyze_traffic(artifacts)
""",
                "variables": {
                    "artifacts": "step.0.siem_analysis.artifacts"
                }
            },
            "template": "Traffic volume and flow behavior analysis concluded with a verdict of {{ output.verdict }}. The evaluation focused on outbound versus inbound traffic ratios, tunneling indicators, and session stability. {% if output.signals %}The analysis identified potential traffic-based threats, including {{ output.signals | join(', ') | replace('_', ' ') }}, which may suggest data exfiltration or covert channel usage.{% else %}Traffic patterns aligned with expected baselines and showed no evidence of exfiltration or tunneling activity.{% endif %}"
        },
        {
            "name": "execute_python",
            "parameters": {
                "code": """
def analyze_threat_intel(artifacts):
    reputations = artifacts.get("reputation_score", [])
    malware_families = artifacts.get("malware_family", [])
    
    signals = []
    
    if any(r in ["malicious", "high-risk", "bad"] for r in reputations):
        signals.append("malicious_reputation_detected")
    
    if malware_families:
         signals.append(f"malware_family_associated:{malware_families[0]}")
         
    return {
        "signals": signals,
        "verdict": "ESCALATE" if signals else "IGNORE"
    }

output = analyze_threat_intel(artifacts)
""",
                "variables": {
                    "artifacts": "step.0.siem_analysis.artifacts"
                }
            },
            "template": "Threat intelligence correlation analysis completed with a verdict of {{ output.verdict }}. The session was assessed for known malicious reputations and associations with recognized malware families. {% if output.signals %}Threat intelligence matches were identified, including {{ output.signals | join(', ') | replace('_', ' ') }}, strengthening confidence in malicious activity.{% else %}No malicious reputation indicators or malware family associations were found in current intelligence feeds.{% endif %}"
        },
        {
            "name": "execute_python",
            "parameters": {
                "code": """
def analyze_policy(artifacts):
    policies = artifacts.get("policy_name", [])
    
    signals = []
    
    if any("any" in str(p).lower() for p in policies):
        signals.append("weak_policy_usage")

    if "exception_applied" in artifacts:
         signals.append("policy_exception_triggered")
         
    return {
        "signals": signals,
        "verdict": "REVIEW" if signals else "IGNORE"
    }

output = analyze_policy(artifacts)
""",
                "variables": {
                    "artifacts": "step.0.siem_analysis.artifacts"
                }
            },
            "template": "Policy and configuration analysis completed with a verdict of {{ output.verdict }}. The evaluation reviewed applied security policies for overly permissive rules and exception usage. {% if output.signals %}Policy-related weaknesses were identified, including {{ output.signals | join(', ') | replace('_', ' ') }}, indicating potential control gaps.{% else %}Policy enforcement appeared consistent with security expectations, with no risky or misconfigured policies detected.{% endif %}"
        },
        {
            "name": "execute_python",
            "parameters": {
                "code": """
def analyze_temporal(artifacts):
    durations = artifacts.get("event_duration", [])
    
    signals = []
    
    short_events = [d for d in durations if d < 10]
    if len(short_events) > 20:
        signals.append("burst_activity_detected")

    long_events = [d for d in durations if d > 3600]
    if long_events:
         signals.append("long_running_session")
         
    return {
        "signals": signals,
        "verdict": "REVIEW" if signals else "IGNORE"
    }

output = analyze_temporal(artifacts)
""",
                "variables": {
                    "artifacts": "step.0.siem_analysis.artifacts"
                }
            },
            "template": "Temporal behavior analysis concluded with a verdict of {{ output.verdict }}. The session was evaluated for burst activity, long-running sessions, and abnormal timing patterns. {% if output.signals %}Timing anomalies were identified, including {{ output.signals | join(', ') | replace('_', ' ') }}, which may indicate automation or persistence behavior.{% else %}Session timing and activity cadence were consistent with normal behavioral baselines.{% endif %}"
        },
        {
            "name": "execute_python",
            "parameters": {
                "code": """
def analyze_correlation(identity_signals,process_signals,network_signals,file_signals,traffic_signals, artifacts):
    
    corr_signals = []

    if "excessive_login_failures" in identity_signals and (
        "tunnel-up" in artifacts.get("event_action", []) or 
        len(artifacts.get("network_bytes_out_total", [])) > 0
    ):
        corr_signals.append("brute_force_success_pattern")

    if process_signals and network_signals:
         corr_signals.append("process_network_correlation")

    if file_signals and traffic_signals:
         corr_signals.append("file_exfil_correlation")
         
    return {
        "signals": corr_signals,
        "verdict": "ESCALATE" if corr_signals else "IGNORE"
    }

output = analyze_correlation(identity_signals,process_signals,network_signals,file_signals,traffic_signals,artifacts)
""",
                "variables": {
                    "identity_signals": "step.2.output.signals",
                    "process_signals": "step.4.output.signals",
                    "network_signals": "step.12.output.signals",
                    "file_signals": "step.5.output.signals",
                    "traffic_signals": "step.13.output.signals",
                    "artifacts": "step.0.siem_analysis.artifacts"
                }
            },
            "template": "Cross-domain correlation analysis completed with a verdict of {{ output.verdict }}. Signals from identity, endpoint, process, file, network, and traffic domains were correlated to identify multi-stage attack patterns. {% if output.signals %}The analysis identified correlated threat activity, including {{ output.signals | join(', ') | replace('_', ' ') }}, indicating a potential attack chain spanning multiple domains.{% else %}No meaningful cross-domain correlations were formed, and observed signals did not combine into a confirmed attack pattern.{% endif %}"
        }
    ]

  
def template():
    """
    Jinja template for overall analysis summary using step_N outputs.
    """
    return """Root cause analysis was conducted across identity, endpoint, process execution, file activity, network behavior, traffic flow, threat intelligence, policy enforcement, temporal patterns, and cross-domain correlation.

{% set step_map = {
  "Identity and Authentication": step_1,
  "Endpoint and EDR Health": step_2,
  "Process Execution": step_3,
  "File Activity": step_4,
  "Network Connections": step_11,
  "Traffic and Flow Behavior": step_12,
  "Threat Intelligence": step_13,
  "Policy and Configuration": step_14,
  "Temporal and Behavioral Patterns": step_15,
  "Cross-Domain Correlation": step_16
} %}

{% set escalations = [] %}
{% set reviews = [] %}

{% for name, step in step_map.items() %}
  {% if step.verdict == "ESCALATE" %}
    {% set _ = escalations.append(name ~ ' (' ~ (step.signals | join(', ') | replace('_', ' ')) ~ ')') %}
  {% elif step.verdict == "REVIEW" %}
    {% set _ = reviews.append(name ~ ' (' ~ (step.signals | join(', ') | replace('_', ' ')) ~ ')') %}
  {% endif %}
{% endfor %}

{% if escalations %}
The session presents high-risk indicators requiring escalation. Elevated risk was identified in {{ escalations | join('; ') }}, where the observed signals indicate potentially malicious or policy-violating behavior and warrant immediate investigation.
{% elif reviews %}
The session demonstrates moderate-risk behavior that merits analyst review. Notable anomalies were observed in <b>{{ reviews | join('; ') }}</b>, and while no confirmed malicious activity was established, additional context and validation are recommended.
{% else %}
No malicious or high-risk indicators were identified across any evaluated domains. All analyzed behaviors, including authentication activity, endpoint posture, execution behavior, file access, network communication, and timing patterns, aligned with expected baselines and do not require further action.
{% endif %}

"""




# {% set escalations = [] %}
# {% set reviews = [] %}

# {% for s in [step_1, step_2, step_3, step_4, step_9, step_10, step_11, step_12, step_13, step_14] %}
#   {% if s.verdict == "ESCALATE" %}
#     {% set _ = escalations.append(loop.index) %}
#   {% elif s.verdict == "REVIEW" %}
#     {% set _ = reviews.append(loop.index) %}
#   {% endif %}
# {% endfor %}

# {% if escalations %}
# The session exhibits high-risk indicators requiring escalation, driven by findings in step(s) {{ escalations | join(', ') }}. Multiple signals across one or more security domains suggest potential malicious or policy-violating activity and warrant immediate investigation.
# {% elif reviews %}
# The session shows moderate-risk behavior that merits analyst review, with noteworthy findings identified in step(s) {{ reviews | join(', ') }}. While no definitive malicious activity was confirmed, observed anomalies may require contextual validation.
# {% else %}
# No malicious or high-risk indicators were identified across the evaluated security domains. All analyzed behaviors aligned with expected baselines, and the session is assessed as benign with no further action required.
# {% endif %}