import platform
import distro
import subprocess
import psutil


def check_os_version():
    system = platform.system()
    version = platform.release()

    if system == "Windows":
        try:
            major = int(version.split(',')[0])
            if major < 10:
                return {'passed': False, 'details': f'Windows version {version} is unsupported.'}
        except Exception:
            return {'passed': False, 'details': 'Could not parse Windows version.'}
    elif system == "Linux":
        info = distro.info()
        name = info.get("id", "").lower()
        ver = info.get("version", "")
        try:
            if "ubuntu" in name and float(ver.split('.')[0]) < 20:
                return {'passed': False, 'details': f'{name.capitalize()} {ver} is EOL'}
        except:
            return {'passed': False, 'details': f'Could not parse Linux version: {name} {ver}'}
        return {'passed': True, 'details': f'{name.capitalize()} {ver} is supported'}
    elif system == "Darwin":
        if int(platform.mac_ver()[0].split(',')[1]) < 12:
            return {'passed': False, 'details': f'Mac version {platform.mac_ver()[0]} is outdated.'}
    return {'passed': True, 'details': f'{system} {version} is supported.'}

def check_python_version():
    import sys
    version_info = sys.version_info
    passed = version_info >= (3, 8)
    details = f"Python version: {version_info}"
    if not passed:
        details += "- Recommended: Python 3.8+"
    return {'passed': passed, 'details': details}

def check_firewall_status():
    if platform.system() != "Windows":
        return {'passed': True, 'details': 'Non-Windows system, skipping firewall check'}

    try:
        output = subprocess.check_output(["netsh", "advfirewall", "show", "allprofiles"], text=True)
        if "State ON" in output:
            return {'passed': True, 'details': f'Firewall {output} is ON for at least one profile'}
        else:
            return {'passed': False, 'details': f'Firewall {output} is OFF on all profiles'}
    except Exception as e:
        return {'passed': False, 'details': 'Error checking firewall: {e}'}

def check_antivirus_status():
    if platform.system() != "Windows":
        return {'passed': True, 'details': 'Non-Windows system, skipping AV check'}

    try:
        result = subprocess.run(
            ['powershell', '-Command', 'Get-MpComputerStatus | Select-Object -ExpandProperty AMServiceEnabled'],
            capture_output=True, text=True)
        if 'True' in result.stdout:
            return {'passed': True, 'details': 'Windows Defender is enabled'}
        else:
            return {'passed': False, 'details': 'Windows Defender is not active'}
    except Exception as e:
        return {'passed': False, 'details': f'AV check error: {e}'}

def check_open_ports():
    risky_ports = {21, 23, 3389, 445, 139}
    connections = psutil.net_connections()
    open_risky = [c.laddr.port for c in connections if c.status == 'LISTEN' and c.laddr.port in risky_ports]

    if open_risky:
        return {'passed': False, 'details': f'Risky ports open: {open_risky}'}
    return {'passed': True, 'details': 'No risky ports open'}

def check_admin_users():
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("net localgroup administrators", text=True)
            users = [line.strip() for line in output.splitlines() if
                     line.strip() and "command completed" not in line.lower()]
            return {'passed': len(users) <= 2, 'details': f'Admin users: {len(users)} → {users}'}
        else:
            output = subprocess.check_output("getent group sudo", shell=True, text=True)
            users = output.strip().split(":")[-1].split(",")
            users = [u.strip() for u in users if u.strip()]
            return {'passed': len(users) <= 2, 'details': f'Sudo users: {len(users)} → {users}'}
    except Exception as e:
        return {'passed': False, 'details': f'Error checking admin users: {e}'}

import platform
import subprocess

def check_password_policy_windows():
    """
    Use PowerShell to query Windows password policy settings.
    Returns a summary string or error message.
    """
    try:
        # Query password policy via net accounts command
        result = subprocess.run(
            ["net", "accounts"],
            capture_output=True, text=True, shell=True, check=True
        )
        output = result.stdout

        # You can parse this output for specific policies, e.g.:
        # Minimum password length, lockout threshold, etc.
        # For now, just return the whole output as details.
        return output.strip()

    except subprocess.CalledProcessError as e:
        return f"Error retrieving Windows password policy: {e}"

def check_password_policy_linux():
    """
    Simple Linux check example for password policy via /etc/login.defs.
    Extend this to parse PAM files or distro-specific configs as needed.
    """
    try:
        with open("/etc/login.defs") as f:
            lines = f.readlines()

        min_len = None
        for line in lines:
            if line.strip().startswith("PASS_MIN_LEN"):
                min_len = line.split()[1]
                break

        if min_len:
            return f"Minimum password length is set to {min_len}"
        else:
            return "Minimum password length not set in /etc/login.defs"

    except Exception as e:
        return f"Error reading /etc/login.defs: {e}"

def run_password_policy_check():
    system = platform.system()
    if system == "Linux":
        details = check_password_policy_linux()
    elif system == "Windows":
        details = check_password_policy_windows()
    else:
        details = f"Unsupported OS for password policy check: {system}"

    passed = "Error" not in details  # crude success check, customize as needed

    return {
        "name": "Password Policy Check",
        "passed": passed,
        "details": details,
    }

def check_auto_updates():
    if platform.system() == "Linux":
        try:
            status = subprocess.getoutput("systemctl is-enabled unattended-upgrades.service")
            if "enabled" in status:
                return {'passed': True, 'details': 'Unattended upgrades are enabled'}
        except:
            pass
        return {'passed': False, 'details': 'Unattended upgrades disabled or not installed'}

    elif platform.system() == "Windows":
        try:
            output = subprocess.check_output(
                ['powershell', '-Command', '(Get-Service wuauserv).Status'],
                text=True)
            if "Running" in output:
                return {'passed': True, 'details': 'Windows Update service is running'}
        except:
            pass
        return {'passed': False, 'details': 'Windows Update service not running'}

    return {'passed': True, 'details': 'Auto-updates check not supported on this platform'}

def check_insecure_services():
    suspicious = ['telnet', 'vsftpd', 'smbd']
    running = subprocess.getoutput("tasklist" if platform.system() == "Windows" else "ps aux")
    found = [svc for svc in suspicious if svc.lower() in running.lower()]
    if found:
        return {'passed': False, 'details': 'Insecure services found'}
    return {'passed': True, 'details': 'No insecure services detected'}

def check_ssh_config():
    if platform.system() == "Windows":
        return {'passed': False, 'details': 'SSH config not applicable on this platform'}

    try:
        with open("/etc/ssh/ssh_config") as f:
            config = f.read()
        issues = []
        if 'PermitRootLogin yes' in config:
            issues.append('PermitRootLogin is enabled')
        if 'PasswordAuthentication yes' in config:
            issues.append('PasswordAuthentication is enabled')
        if issues:
            return {'passed': False, 'details': f'SSH issues {issues}'}
        return {'passed': True, 'details': 'SSH configuration is secure'}
    except Exception as e:
        return {'passed': False, 'details': f'Error checking SSH config: {e}'}

def check_disk_encryption():
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output(["manage-bde", "-status"], text=True)
            if "Percentage Encrypted: 100%" in output:
                return {'passed': True, 'details': 'Bitlocker fully enabled'}
            else:
                return {'passed': False, 'details': 'Bitlocker not fully enabled'}
        except:
            return {'passed': False, 'details': 'Error checking disk encryption'}
    elif platform.system() == "Linux":
        output = subprocess.getoutput("lsblk -o NAME,TYPE,MOUNTPOINT | grep crypt")
        if output.strip():
            return {'passed': True, 'details': 'Encrypted volume(s) detected'}
        return {'passed': False, 'details': 'Encrypted volume(s) not detected'}
    elif platform.system() == "Darwin":
        output = subprocess.getoutput("fdesetup status")
        if "FileVault is On" in output:
            return {'passed': True, 'details': 'FileVault is enabled'}
        return {'passed': False, 'details': 'FileVault is not enabled'}
    return {'passed': False, 'details': 'Unable to check encryption'}

def run_audits():
    checks = {
        "OS Version": check_os_version,
        "Firewall Status": check_firewall_status,
        "Antivirus Status": check_antivirus_status,
        "Open Ports": check_open_ports,
        "Admin/Sudo Users": check_admin_users,
        "Password Policy": run_password_policy_check(),
        "Auto Updates": check_auto_updates,
        "Insecure Services": check_insecure_services,
        "SSH Config": check_ssh_config,
        "Disk Encryption": check_disk_encryption,
    }

    results = {}
    for name, func in checks.items():
        try:
            results[name] = func()
        except Exception as e:
            results[name] = {'passed': False, 'details': f'Error: {e}'}

    return results