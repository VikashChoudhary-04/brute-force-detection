# MITRE ATT&CK Mapping

- This file documents the MITRE ATT&CK techniques related to detections and investigations performed in this brute force detection project.

---

## ATT&CK Overview

- MITRE ATT&CK is a framework that documents:
  - Adversary tactics
  - Attack techniques
  - Threat behaviors
  - Real-world attack patterns

- It helps SOC analysts:
  - Categorize detections
  - Improve visibility
  - Understand attacker methodology
  - Standardize investigations

---

## Detection Mapping

| Detection Activity | ATT&CK Technique | Technique ID | Tactic |
|---|---|---|---|
| Failed Login Monitoring | Brute Force | T1110 | Credential Access |
| Successful Login Correlation | Valid Accounts | T1078 | Defense Evasion |
| PowerShell Monitoring | PowerShell | T1059.001 | Execution |
| LOLBin Monitoring | Signed Binary Proxy Execution | T1218 | Defense Evasion |
| Process Creation Monitoring | Command and Scripting Interpreter | T1059 | Execution |

---

## Technique Details

---

### T1110 — Brute Force

#### Description

- Attackers attempt repeated authentication attempts to gain unauthorized access.

#### Common Attack Types

- Password guessing
- Password spraying
- Credential stuffing

#### Detection Relevance

- Failed login monitoring helps identify:
  - Repeated authentication failures
  - Account targeting
  - Authentication abuse

#### Relevant Telemetry

- Windows Event ID 4625
- Authentication logs
- Sign-in telemetry

---

### T1078 — Valid Accounts

#### Description

- Attackers use legitimate credentials to access systems and evade detection.

#### Detection Relevance

- Successful authentication after repeated failures may indicate:
  - Successful brute force attacks
  - Credential compromise
  - Unauthorized access

#### Relevant Telemetry

- Event ID 4624
- Authentication logs
- Privileged account activity

---

### T1059.001 — PowerShell

#### Description

- Attackers abuse PowerShell for:
  - Payload execution
  - Malware delivery
  - Automation
  - Persistence

#### Detection Relevance

- Suspicious PowerShell activity may indicate:
  - Malware execution
  - Post-exploitation activity
  - Lateral movement

#### Relevant Telemetry

- Process creation logs
- PowerShell command lines
- Script execution events

---

### T1218 — Signed Binary Proxy Execution

#### Description

- Attackers abuse legitimate Windows binaries (LOLBins) to execute malicious code.

#### Common LOLBins

- rundll32.exe
- mshta.exe
- regsvr32.exe
- certutil.exe

#### Detection Relevance

- LOLBin monitoring helps identify:
  - Defense evasion
  - Suspicious command execution
  - Proxy execution techniques

---

### T1059 — Command and Scripting Interpreter

#### Description

- Attackers use scripting interpreters to automate malicious activity and execute commands.

#### Detection Relevance

- Monitoring scripting interpreters improves visibility into:
  - Malware execution
  - Suspicious scripts
  - Command execution behavior

#### Relevant Processes

- powershell.exe
- cmd.exe
- wscript.exe
- cscript.exe

---

## SOC Analyst Value

- MITRE ATT&CK mapping helps analysts:
  - Understand attacker behavior
  - Improve detection quality
  - Build stronger investigations
  - Standardize detection logic

---

## Key Lessons Learned

- Detection logic should align with attacker techniques
- ATT&CK mapping improves investigation context
- Authentication telemetry is critical for credential attack detection
- Threat hunting improves visibility into suspicious activity
- Detection engineering combines technical and contextual analysis

---

## Project Context

- This ATT&CK mapping was created as part of a beginner SOC detection engineering project using:
  - Splunk
  - Windows Event Logs
  - Sigma rules
  - Authentication telemetry
  - Threat hunting workflows
