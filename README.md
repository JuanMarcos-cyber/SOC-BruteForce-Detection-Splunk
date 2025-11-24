# 🔐 Brute Force Attack Detection Using Splunk  
**MITRE ATT&CK Technique:** T1110.001 — *Brute Force: Password Guessing*  
**Objective:** Detect repeated authentication failures from the same source attempting to gain unauthorized access.

---

### 📌 Overview  
This project demonstrates the detection of brute force authentication attempts using **Windows Event Logs** analyzed in **Splunk**.  
The investigation maps raw log data to the **MITRE ATT&CK framework** and documents the **queries, evidence, and recommended mitigations**.

---

### 🧪 Detection Methodology  
#### ✔️ **Data Source**
- Windows Security Logs
- Event ID **4625** (Failed Login)

#### 🔎 **Splunk Query**
index=* sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 5 AND Source_Network_Address!="-"
| sort -count


---

### 🎯 Detection Criteria  
| Indicator | Description |
|-----------|-------------|
| Multiple consecutive failed logins | Same username |
| Repeated attempts from a single IP | Same source |
| High frequency in a short time | Timing patterns |

---

### 🎭 Mapping to MITRE ATT&CK  
| MITRE ID | Technique | Relevant Indicator |
|----------|-----------|------------------|
| T1110.001 | Brute Force: Password Guessing | High volume failed logins (Event 4625) |

---

### 📸 Evidence  
📌 *Screenshots and log excerpts will be added in `/Evidence` folder.*

---

### 🛡 Recommended Mitigations  
| Control Type | Recommendation |
|--------------|----------------|
| Technical | Enforce strong password policy |
| Technical | Implement account lockout threshold |
| Monitoring | Create alerts in SIEM (Splunk) |
| Policy | MFA enforcement on privileged accounts |

---

### 📎 Related Standards  
| Framework | Reference |
|-----------|-----------|
| MITRE ATT&CK | T1110 — Brute Force |
| NIST 800-53 | **AC-2**, **IA-5**, **AU-6** |
| CIS Controls | 4.5, 16.3 |

---

### 👤 Author  
**Juan Marcos Lázaro Rey**  
Cybersecurity Professional — SOC & GRC  
Miami, FL, USA

---

### 📂 Repository Structure  
/SOC-BruteForce-Detection-Splunk
│── README.md
│── /Evidence
│── /Queries
│── /Docs

### 🔄 Next Steps  
- Upload screenshots in `/Evidence`
- Add real log samples (sanitized)
- Optional: Enrich data with geolocation lookup
- 
