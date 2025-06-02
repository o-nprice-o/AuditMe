import json
import platform
if platform.system() == "Linux":
    import distro
import subprocess
import psutil
import re
if platform.system() == "Windows":
    import ctypes


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
    try:
        cmd = ["powershell", "-Command", "Get-NetFirewallProfile | Select-Object -Property Name, Enabled | ConvertTo-Json"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        profiles = json.loads(result.stdout)
        all_enabled = all(p["Enabled"] for p in profiles)
        return {
            "passed": all_enabled,
            "details": "All firewall profiles enabled" if all_enabled else "One or more firewall profiles are disabled"
        }
    except Exception as e:
        return {"passed": False, "details": f"Error checking firewall: {e}"}

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
    try:
        conns = psutil.net_connections()
        open_ports = [c.laddr.port for c in conns if c.status == 'LISTEN']
        if open_ports:
            return {"passed": False, "details": f"Listening ports found: {open_ports}"}
        else:
            return {"passed": True, "details": "No listening ports found"}
    except Exception as e:
        return {"passed": False, "details": f"Error checking open ports: {e}"}

def check_admin_users():
    try:
        cmd = ['powershell', '-Command', 'net localgroup administrators']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        lines = result.stdout.splitlines()

        # Filter only the member entries
        members = []
        in_members = False
        for line in lines:
            line = line.strip()
            if not line or "command completed" in line.lower():
                continue
            if line.startswith("---"):
                in_members = True
                continue
            if in_members:
                members.append(line)

        passed = len(members) > 0
        return {
            "passed": passed,
            "details": f"Administrator group members: {', '.join(members)}" if passed else "No members found in Administrators group"
        }
    except Exception as e:
        return {"passed": False, "details": f"Error checking admin users: {e}"}

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

def is_admin():
    """Check if the script is running with admin rights (Windows only)."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_disk_encryption():
    system = platform.system()

    if system == "Windows":
        if not is_admin():
            return {
                "passed": False,
                "details": "Insufficient privileges to check BitLocker status. Please run as Administrator."
            }

        try:
            result = subprocess.run(
                ['powershell', '-Command', 'manage-bde -status C:'],
                capture_output=True, text=True, check=True
            )
            output = result.stdout

            protection_on = re.search(r'Protection Status:\s+Protection On', output)
            full_encryption = re.search(r'Percentage Encrypted:\s+100(?:\.0)?%', output)

            if protection_on and full_encryption:
                return {"passed": True, "details": "BitLocker is ON and drive is 100% encrypted"}
            else:
                return {"passed": False, "details": "BitLocker not fully enabled or partially encrypted"}
        except subprocess.CalledProcessError as e:
            return {"passed": False, "details": f"BitLocker check failed: {e}"}
        except Exception as e:
            return {"passed": False, "details": f"Unexpected error: {e}"}

    elif system == "Linux":
        output = subprocess.getoutput("lsblk -o NAME,TYPE,MOUNTPOINT | grep crypt")
        if output.strip():
            return {'passed': True, 'details': 'Encrypted volume(s) detected'}
        return {'passed': False, 'details': 'Encrypted volume(s) not detected'}

    elif system == "Darwin":  # macOS
        output = subprocess.getoutput("fdesetup status")
        if "FileVault is On" in output:
            return {'passed': True, 'details': 'FileVault is enabled'}
        return {'passed': False, 'details': 'FileVault is not enabled'}

    return {'passed': False, 'details': 'Unable to check encryption on this OS'}

def run_audits(module=None, verbose=False):
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