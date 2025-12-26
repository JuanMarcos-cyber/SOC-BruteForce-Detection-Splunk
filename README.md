# 🔐 Brute Force Attack Detection Using Splunk  
**MITRE ATT&CK Technique:** T1110.001 — *Brute Force: Password Guessing*  
**Objective:** Detect repeated authentication failures from the same source attempting to gain unauthorized access.

---

### 📌 Overview  
This project demonstrates the detection of an SSH brute force attack using Linux  
`linux_secure` logs ingested into **Splunk SIEM**. A scripted attack generates multiple  
failed SSH logins, which are then detected and correlated using SPL queries.

The investigation maps raw log data to the **MITRE ATT&CK** framework and documents:
- Detection queries  
- Evidence from Splunk (alerts + results)  
- Recommended mitigations aligned to common security standards  

---

### 🧪 Detection Methodology  
#### ✔️ **Data Source**
- Linux `linux_secure` authentication logs  
- SSH `Failed password` and `Accepted password` entries

#### 🔎 **Splunk Queries**

**📌 Brute Force Detection — SSH (Linux)**  
```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "Failed password for (?<username>\S+) from (?<src_ip>\S+)"
| stats count as failed_attempts by username, src_ip, host
| where failed_attempts >= 3
| sort -failed_attempts
```

🔄 Correlation with Successful Logins

index=main sourcetype=linux_secure (("Failed password" OR "Accepted password") AND ssh*)
| rex field=_raw "(?<auth_result>Failed|Accepted) password for (?<username>\S+) from (?<src_ip>\S+)"
| eval auth_status=if(match(_raw, "Failed"), "Failed", "Success")
| table _time, auth_status, username, src_ip
| sort _time

🎯 Detection Criteria
| Indicator                          | Description     |
| ---------------------------------- | --------------- |
| Multiple consecutive failed logins | Same username   |
| Repeated attempts from a single IP | Same source     |
| High frequency in a short time     | Timing patterns |


🎭 Mapping to MITRE ATT&CK
| MITRE ID      | Technique                      | Relevant Indicator                                             |
| ------------- | ------------------------------ | -------------------------------------------------------------- |
| **T1110.001** | Brute Force: Password Guessing | High volume of `Failed password` attempts from a single source |


📸 Evidence
📌 Screenshots and log excerpts are stored in the /Evidence folder.

🛡 Recommended Mitigations
| Control Type | Recommendation                      |
| ------------ | ----------------------------------- |
| Technical    | Enforce strong password policy      |
| Technical    | Implement account lockout threshold |
| Monitoring   | Create alerts in SIEM (Splunk)      |
| Policy       | Enforce MFA on privileged accounts  |


📎 Related Standards
| Framework    | Reference                    |
| ------------ | ---------------------------- |
| MITRE ATT&CK | T1110 — Brute Force          |
| NIST 800-53  | **AC-2**, **IA-5**, **AU-6** |
| CIS Controls | 4.5, 16.3                    |


📂 Repository Structure

```text
/SOC-BruteForce-Detection-Splunk
│── README.md
│── /Docs
│── /Evidence
│── /Queries
```

# 🙌 Author

**Juan Marcos Lázaro**  
Cloud Security & GRC Professional  
Miami, FL  
LinkedIn: https://www.linkedin.com/in/juanmarcoslazaro
