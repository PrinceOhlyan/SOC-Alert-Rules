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

splunk
index=wineventlog EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 5

---

##🔸 Suspicious PowerShell Execution

index=wineventlog EventCode=4104
| search Message="*EncodedCommand*"
| stats count by User, ComputerName


---

##🔸 Failed RDP Login Attempts

index=wineventlog EventCode=4625 Logon_Type=10
| stats count by Account_Name, Source_Network_Address
| where count > 3


---

##🔸 Potential Malware Beaconing (DNS Pattern)

index=dns_logs
| stats count by query
| where like(query, "%.%.%.%") OR like(query, "%.%.%.%.%")


---

## MITRE ATT&CK Mappings

Detection	ATT&CK Technique
Brute Force Login	T1110
PowerShell Abuse	T1059.001
RDP Brute Force	T1110
Malware Beaconing	T1071.004


---

Future Work
	•	Add more Splunk rules
	•	Write Sigma rules for ELK Stack
	•	Automate IOC extraction

---

Author

Prince Ohlyan | Certified Security Analyst (CSA-EC Council)

LinkedIn: Prince Ohlyan
