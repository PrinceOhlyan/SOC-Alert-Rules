# SOC Alert Rules & Detection Queries

This repository contains a collection of detection queries, alert rules, and hunting queries I have written and tested during my cybersecurity labs, SOC Analyst internship, and self-learning.

These queries are designed to detect suspicious activities across Windows environments, network traffic, and web applications. The goal is to contribute to threat detection and improve incident response capabilities.

## Tools used
- Splunk Enterprise (Trial)
- Windows Sysmon
- Windows Event Logs
- MITRE ATT&CK Framework
- ELK Stack (for some tests)
- Kali Linux & Metasploit (for generating attacks)

---

## Current Detection Rules

### 🔸 Brute Force Login Detection (Windows)

```splunk
index=wineventlog EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 5
