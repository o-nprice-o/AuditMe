# 🛡️ auditme

**auditme** is a modular Python-based security audit tool designed to check system configurations, security policies, and common misconfigurations. It works across Windows, Linux, and macOS with several built-in audits.

---

## ✅ Features

- OS version check  
- Firewall status  
- Antivirus presence  
- Open ports listener scan  
- Admin/sudo user listing  
- Password policy enforcement check  
- Automatic updates enabled  
- Insecure services detection  
- SSH configuration check  
- Disk encryption verification  

---

## 📦 Requirements

- Python 3.8+
- Run in an environment with appropriate privileges (some checks require elevated/admin rights)

### Install dependencies:

```bash
pip install -r requirements.txt

    On Windows, run PowerShell as Administrator for full access to all checks (especially BitLocker and firewall).

🚀 Usage
Run the full audit:

python auditme.py

Verbose mode (includes detailed check results):

python auditme.py --verbose

Run a specific module (if modular structure is expanded):

python auditme.py --module base

⚠️ Notes

    Windows users: For full audit coverage, run the tool from an elevated PowerShell or command prompt.

    Linux/macOS users: Some checks may require sudo (e.g., disk encryption, SSH config).

🔜 Coming Soon

    CVE lookup and vulnerability scoring

    Export results to JSON or HTML

    Remediation suggestions

    GUI frontend
