# Adaptive Web Application Firewall (WAF) 🔒

## 📌 Overview
This repository contains the source code, simulation files, and resources for the **Adaptive Web Application Firewall (WAF)** developed as part of the research work published in IEEE.  
The WAF is designed to detect and block multiple types of web-based attacks in real-time, including:
- **SQL Injection (SQLi)**
- **Cross-Site Scripting (XSS)**
- **Directory Traversal**
- **Distributed Denial of Service (DDoS)**

The system integrates **Python-based detection modules**, pre-defined **attack signature patterns**, and **GNS3-based network simulation** for testing.  
It can be run locally via Command Prompt (CMD) for demonstration and testing purposes.

📄 **Research Paper (IEEE Xplore)**: [Click here to view](<https://ieeexplore.ieee.org/document/10823239>)

---

#### 1. Start the backend server (if your WAF requires one)
python backend_server.py

### 2. Run the WAF
python waf.py

### 3. Test attacks using a .txt file
python test_attacks.py --file attacks.txt

### 4. Run attack simulation (for stress testing and visualization)
python simulate_attacks.py

### 5. Optional: Test with DVWA (requires XAMPP/WAMP setup and DVWA installation)
  - Start Apache and MySQL
  - Navigate to DVWA in browser and configure security level
  - Run WAF and attack scripts
