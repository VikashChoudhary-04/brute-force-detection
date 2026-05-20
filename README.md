# Brute Force Detection Project

## Overview

- This project demonstrates a SOC detection engineering workflow focused on identifying brute force authentication activity using:

  - Splunk SPL
  - Windows Security Event Logs
  - Sigma rules
  - MITRE ATT&CK mapping
  - Authentication telemetry analysis
  - SOC investigation methodology

- The project simulates how a SOC analyst or detection engineer would:

  1. Monitor failed authentication attempts
  2. Detect brute force behavior
  3. Investigate authentication anomalies
  4. Build detection logic
  5. Analyze suspicious login patterns
  6. Document findings professionally

---

## Objectives

### Primary Goal

- Detect authentication activity that may indicate:

  - Brute force attacks
  - Password spraying
  - Credential stuffing
  - Repeated account targeting
  - Authentication abuse

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Splunk Free | SIEM platform |
| Windows Event Logs | Authentication telemetry |
| SPL | Detection queries |
| Sigma | Portable detection rules |
| MITRE ATT&CK | Threat mapping |

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Brute Force | T1110 | Credential Access |
| Valid Accounts | T1078 | Defense Evasion |

---

## Windows Event IDs Used

| Event ID | Description |
|---|---|
| 4625 | Failed Login |
| 4624 | Successful Login |
| 4672 | Privileged Logon |

---

## Detection Goals

- This project focuses on detecting:

  - Excessive failed logins
  - Repeated account targeting
  - Login spikes
  - Suspicious authentication patterns
  - Successful logins after repeated failures

---

## Example Splunk Detection Query

```spl
index=main "4625"
| stats count by Account
| where count > 5
| sort - count
```

---

## Detection Engineering Concepts

- This project explores:

  * Authentication monitoring
  * Threshold-based detections
  * Time-based correlation
  * Brute force detection logic
  * SOC triage methodology
  * Threat hunting workflows

---

## Sigma Detection Example

```yaml id="m4tx8r"
title: Excessive Failed Login Attempts

description: Detects repeated failed authentication attempts that may indicate brute force activity.

logsource:
  product: windows
  service: security

detection:
  selection:
    EventID: 4625

  condition: selection

level: medium
```

---

## Investigation Workflow

1. Review failed login events
2. Identify targeted accounts
3. Analyze authentication timing
4. Investigate successful logins after failures
5. Determine severity
6. Escalate suspicious activity

---

## False Positives

- Potential benign causes:

  * Incorrect passwords
  * Expired credentials
  * VPN authentication issues
  * Misconfigured services
  * User login mistakes

---

## SOC Skills Demonstrated

* Splunk log analysis
* Detection engineering fundamentals
* Authentication monitoring
* SPL query development
* Sigma rule creation
* ATT&CK mapping
* SOC investigation workflows
* Threat hunting basics

---

## Future Improvements

Potential enhancements include:

* Source IP correlation
* Password spraying detection
* MFA failure monitoring
* Alert automation
* Time-window detections
* Threat intelligence integration

---

## Project Status

- Active SOC detection engineering learning project focused on authentication threat detection and brute force monitoring.
