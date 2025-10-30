# AI-Related Threat Hunt — Keyword & Behavior Search (no CVE)

> **Author:** Brian Maroney  
> **Date:** 2025-01-08  
> **Status:** experimental  
> **Severity:** High

---

## Purpose
Hunt for activity that indicates misuse of AI tooling, data-exfiltration using AI endpoints, automated reconnaissance leveraging “AI/GPT/ML” tooling, or actors using AI-branded infrastructure. This is a behavior- and keyword-first hunt (no CVE) to surface suspicious processes, network connections, and file activity that reference AI-related terms or unusual domains/TLDs.

---

## Scope / Objectives
1. **Processes**
   - Find process names or command lines containing AI-related keywords: `AI`, `GPT`, `LLM`, `ML`, `machine-learning`, `automate`, `automation`, `scan`, `recon`, `analyze`, `agent`, `assistant`, `chatbot`.
   - Exclude benign/known terms such as `domain`, `maintenance`, `backup`, `monitoring` (tune per environment).
   - Iteratively refine to reduce noise — e.g., require keyword **and** suspicious flags or network activity.

2. **Network Connections**
   - Detect outbound or inbound connections to suspicious TLDs and domains: `.ai`, `.ml`, `.tech`, `.io`, (plus any org-specific suspicious hosts).
   - Focus on web ports: `80`, `443`, `8080`, `8443` — but also log other unusual outbound ports.
   - Watch for frequent short-lived connections to many `.ai`/.ml domains or large POSTs with potential data payloads.

3. **File Paths**
   - Flag unusual file paths or dropped artifacts that reference AI tooling (e.g., `*/gpt/`, `*/llm/`, `*/xmrig-*gpt*` — adjust examples).
   - Exclude common Windows program paths: `C:\Program Files\`, `C:\Windows\` to reduce false positives.
   - Pay attention to `/tmp`, `/var/tmp`, user Downloads, application local data, or cloud-sync folders.

---

## Metadata (YAML)
```yaml
title: "AI-Related Threat Hunt — Keyword & Behavior (no CVE)"
id: "<uuid-or-unique-id>"
status: experimental
author: "Brian Maroney"
date: "2025-01-08"
tags:
  - threat-hunt
  - ai
  - gpt
  - ml
  - reconnaissance
  - data-exfiltration
logsource:
  category: endpoint, network, proxy, dns, cloud
  product: generic
level: high
description: >
  Hunt for AI/GPT/ML related activity in processes, network, and file paths.
  Use keyword filters + exclusions to reduce false positives and correlate with
  telemetry (network, EDR, proxy) for higher confidence.

```
---

## Detection Logic (YAML)
```yaml

detection:
  processes_with_ai_keywords:
    # Look for AI/GPT/ML keywords in process names or command lines
    process.name|re: "(?i).*(ai|gpt|llm|ml|machine[-_ ]learning|automate|automation|agent|assistant|chatbot|scan|recon|analyz(e|ing)).*"
    process.command_line|re: "(?i).*(ai|gpt|llm|ml|machine[-_ ]learning|automate|automation|agent|assistant|chatbot|scan|recon|analyz(e|ing)).*"
    # Exclusions to reduce noise
    process.command_line|re_not: "(?i).*(domain|maintenance|backup|monitoring|windows-update|sccm).*"

  suspicious_network_domains:
    # Network / DNS / Proxy calls to AI-related TLDs and domain patterns
    dns.qry.name|re: "(?i).*\\.(ai|ml|tech|io)$"
    http.host|re: "(?i).*\\.(ai|ml|tech|io)$"
    network.destination_port:
      - 80
      - 443
      - 8080
      - 8443

  suspicious_file_paths:
    # Unusual file paths and common transient directories
    file.path|re: "(?i).*(/tmp/|/var/tmp/|/home/.*/Downloads/|/root/|/opt/|/usr/local/).*"
    file.path|re: "(?i).*(gpt|llm|ai|assistant|chatbot|agent).*"
    # Exclude common Windows program locations
    file.path|not_contains:
      - "C:\\Program Files\\"
      - "C:\\Windows\\"

  enrichment_and_correlation:
    - correlate(processes_with_ai_keywords, suspicious_network_domains, suspicious_file_paths)
    - require_additional_signal: [process_creation, network_upload > 100KB, suspicious_user_account, external_reputation]

  exclusions:
    src_ip|in:
      - "10.0.0.0/8"
      - "192.168.0.0/16"
      - "172.16.0.0/12"
    known_user_agents:
      - "Legitimate-AI-Tooling-Agent"  # replace with org-known agents

  condition: (processes_with_ai_keywords OR suspicious_network_domains OR suspicious_file_paths) AND NOT exclusions

```
---

## Splunk Query
```yaml
index=endpoint OR index=sysmon sourcetype=process
| eval cmd_lower = lower(process_command_line)
| where match(process_name, "(?i).*(ai|gpt|llm|ml|machine[-_ ]learning|automate|automation|agent|assistant|chatbot|scan|recon|analyz)")
   OR match(cmd_lower, "(?i).*(ai|gpt|llm|ml|machine[-_ ]learning|automate|automation|agent|assistant|chatbot|scan|recon|analyz)")
| where NOT match(cmd_lower, "(?i).*(domain|maintenance|backup|monitoring|windows-update|sccm)")
| table _time host user process_name process_command_line parent_process
| stats count earliest(_time) as first_seen latest(_time) as last_seen values(user) as users values(host) as hosts by process_name process_command_line
| sort - count

