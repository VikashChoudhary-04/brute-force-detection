# Brute Force Detection Queries (Splunk SPL)

- This file contains Splunk SPL queries used for brute force authentication detection and investigation.

---

## 1. Basic Failed Login Detection

```spl
index=main "4625"
| stats count by Account
| where count > 5
| sort - count
````

### Purpose

- Identify accounts experiencing excessive failed authentication attempts.

### Detection Goal

- Detect:

  * Brute force attempts
  * Password guessing
  * Repeated account targeting

---

## 2. Failed Login Timeline

```spl 
index=main "4625"
| timechart count
```

### Purpose

- Visualize failed authentication activity over time.

### Detection Goal

- Identify:

  * Authentication spikes
  * Abnormal login patterns
  * Attack bursts

---

## 3. Top Targeted Accounts

```spl id="6cq7pj"
index=main "4625"
| top Account
```

### Purpose

- Identify accounts receiving the highest number of failed login attempts.

### Detection Goal

- Detect:

  * Account targeting
  * Password spraying
  * Privileged account attacks

---

## 4. Successful Login After Failed Attempts

```spl id="9w9e1j"
index=main ("4624" OR "4625")
| stats count by Account
| sort - count
```

### Purpose

- Review authentication activity involving both successful and failed logins.

### Detection Goal

- Identify:

  * Potential brute force success
  * Suspicious authentication sequences
  * Account compromise indicators

---

## 5. Privileged Logon Monitoring

```spl id="7m3gwy"
index=main "4672"
| stats count by host
| sort - count
```

### Purpose

- Monitor privileged authentication events.

### Detection Goal

- Identify:

  * Administrative account activity
  * Potential privileged access abuse
  * Sensitive account usage

---

## 6. Authentication Spike Detection

```spl id="b9l6ma"
index=main "4625"
| bucket _time span=5m
| stats count by _time
| where count > 10
```

### Purpose

- Detect spikes in failed login activity.

### Detection Goal

- Identify:

  * Brute force bursts
  * Password spraying campaigns
  * Automated login attacks

---

## 7. Suspicious PowerShell Hunting

```spl id="1du8s0"
index=main ("powershell" OR "cmd.exe" OR "rundll32" OR "mshta")
```

### Purpose

- Hunt for suspicious command execution associated with attacker activity.

### Detection Goal

- Identify:

  * LOLBin abuse
  * Suspicious scripting activity
  * Potential post-exploitation behavior

---

## Event IDs Used

| Event ID | Description      |
| -------- | ---------------- |
| 4625     | Failed Login     |
| 4624     | Successful Login |
| 4672     | Privileged Logon |
| 4688     | Process Creation |

---

## MITRE ATT&CK Mapping

| Detection                       | ATT&CK Technique       |
| ------------------------------- | ---------------------- |
| Failed Login Monitoring         | T1110 - Brute Force    |
| Successful Login After Failures | T1078 - Valid Accounts |
| PowerShell Hunting              | T1059.001 - PowerShell |
| Privileged Activity Monitoring  | T1078 - Valid Accounts |

---

## Detection Engineering Concepts

- This project demonstrates:

  * Authentication monitoring
  * Threshold-based detections
  * Time-based analysis
  * Brute force detection logic
  * Threat hunting fundamentals
  * SOC investigation workflows

---

## Notes

- These queries were developed as part of a beginner SOC detection engineering learning project using:

  * Splunk
  * Windows Event Logs
  * Authentication telemetry
  * MITRE ATT&CK mapping
