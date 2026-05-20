# Brute Force Investigation Report

## Investigation Title

- Windows Authentication Brute Force Detection Investigation

---

## Objective

- Investigate Windows authentication telemetry to identify potential brute force authentication activity and suspicious login behavior.

---

## Environment

| Component | Details |
|---|---|
| SIEM | Splunk Free |
| Log Source | Windows Security Logs |
| Investigation Type | Authentication Monitoring |
| Dataset | Windows Authentication Events |
| Host | Vikash |

---

## Event IDs Reviewed

| Event ID | Description |
|---|---|
| 4625 | Failed Login |
| 4624 | Successful Login |
| 4672 | Privileged Logon |
| 4688 | Process Creation |

---

## Investigation Workflow

### 1. Failed Login Detection

#### SPL Query

```spl
index=main "4625"
| stats count by Account
| where count > 5
| sort - count
````

#### Purpose

- Identify accounts experiencing excessive failed login attempts.

#### Findings

- Authentication failures were reviewed to identify potential brute force activity and repeated account targeting.

- No confirmed brute force attack was identified in the current baseline dataset.

---

### 2. Failed Login Timeline Analysis

#### SPL Query

```spl id="g35m9v"
index=main "4625"
| timechart count
```

#### Purpose

- Visualize failed authentication activity over time.

#### Findings

- Authentication activity was analyzed for:

  * Login spikes
  * Burst activity
  * Unusual authentication timing

- No major authentication spikes were identified.

---

### 3. Successful Login Correlation

#### SPL Query

```spl id="k1f7xt"
index=main ("4624" OR "4625")
| stats count by Account
| sort - count
```

#### Purpose

- Review whether successful authentication occurred after repeated failures.

#### Findings

- Successful authentication events were reviewed to determine whether failed login attempts may have resulted in account compromise.

- No evidence of confirmed compromise was identified.

---

### 4. Privileged Logon Monitoring

#### SPL Query

```spl id="f2s4hk"
index=main "4672"
| stats count by host
| sort - count
```

#### Purpose

- Monitor privileged authentication activity.

#### Findings

- Privileged logon activity appeared consistent with expected baseline Windows behavior.

- No suspicious privileged escalation activity was identified.

---

### 5. Suspicious Process Hunting

#### SPL Query

```spl id="20j98m"
index=main ("powershell" OR "cmd.exe" OR "rundll32" OR "mshta")
```

#### Purpose

- Hunt for suspicious command execution potentially associated with attacker activity.

#### Findings

- No suspicious PowerShell activity or LOLBin abuse was identified in the dataset.

---

## MITRE ATT&CK Mapping

| Activity                     | ATT&CK Technique                      |
| ---------------------------- | ------------------------------------- |
| Failed Login Monitoring      | T1110 - Brute Force                   |
| Successful Login Correlation | T1078 - Valid Accounts                |
| PowerShell Monitoring        | T1059.001 - PowerShell                |
| LOLBin Monitoring            | T1218 - Signed Binary Proxy Execution |

---

## SOC Analyst Assessment

- The reviewed dataset primarily reflected normal Windows authentication and system activity.

- No confirmed brute force attacks, credential compromise, suspicious PowerShell execution, or malicious command activity were identified during the investigation.

---

## Key Lessons Learned

* Authentication monitoring is foundational SOC work
* Brute force detection requires threshold analysis
* Baseline behavior understanding is critical
* Detection engineering involves both logic and context
* False positives must always be evaluated carefully
* Threat hunting improves investigation depth

---

## Analyst Notes

- This investigation was conducted as part of a beginner SOC detection engineering learning project focused on brute force authentication monitoring using Splunk, Windows Event Logs, Sigma rules, and MITRE ATT&CK mapping.
