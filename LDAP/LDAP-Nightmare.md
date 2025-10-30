# LDAP Nightmare (CVE-2024-49112 / CVE-2024-49113)

> **Author:** Brian Maroney  
> **Date:** 2025-01-04  
> **Status:** experimental  
> **Severity:** High

---

## Purpose
Detect attempts to exploit **LDAP Nightmare** — two LDAP vulnerabilities disclosed in December 2024 (CVE-2024-49112: RCE, CVE-2024-49113: DoS) that can cause LSASS crashes and, in some exploit variants, enable remote code execution. Primary detection focuses on LSASS application error events referencing **WLDAP32.dll** and on indicators of fake PoC/tooling being used to lure researchers/victims into running malware. :contentReference[oaicite:0]{index=0}

---

## Metadata (YAML)
```yaml
title: LDAP Nightmare Exploit Detection (CVE-2024-49112 / CVE-2024-49113)
id: ldapnightmare-cve-2024-49112-49113
status: experimental
description: >
  Detects LSASS crashes referencing WLDAP32.dll (Event ID 1000) and
  indicators of PoC/malware artifacts observed in the wild that are
  associated with LDAPNightmare activity and lures.
author: Brian Maroney
date: 2025-01-04
tags:
  - cve.2024-49112
  - cve.2024-49113
  - attack.execution
  - attack.dos
  - product.microsoft.windows
logsource:
  category: application
  product: windows
level: high

```

---

## Logic
```yaml

detection:
  ldapnightmare_lsass_crash:
    # LSASS application error events indicating WLDAP32.dll faulting (Event ID 1000)
    EventID: 1000
    faulting.application|contains: "lsass.exe"
    faulting.module|contains: "WLDAP32.dll"

  ldapnightmare_poc_or_malware_indicators:
    # Known PoC/malware artifacts / lures observed in the wild
    file.name|contains:
      - "poc.exe"
    url|contains:
      - "ftpupload.net/htdocs"
      - "pastebin.com/raw/9TxS7Ldc"
      - "ftp.drivehq.com/wwwhome"
    file.hash.md5:
      - "ef4ba8eef919251f7502c7e66926bb3a5422065b"
      - "d4a35487b95cc2b44395047717358bb2863a5311"

  correlation_enrichment:
    - dce_rpc_activity
    - cldap_traffic
    - firewall_external_connections
    - patch_management

```

---

## Splunk Query
```yaml
index=windows EventCode=1000
| eval msg_lower=lower(Message)
| where like(msg_lower, "%faulting application:%lsass.exe%") AND like(msg_lower, "%faulting module:%wldap32.dll%")
| rex field=Message "Faulting application:\\s+(?<faulting_app>[^\r\n]+)"
| rex field=Message "Faulting module:\\s+(?<faulting_module>[^\r\n]+)"
| table _time host ComputerName Account Domain faulting_app faulting_module Message
| stats count earliest(_time) as first_seen latest(_time) as last_seen values(host) as hosts by faulting_app faulting_module
| where count > 0
| sort - count


