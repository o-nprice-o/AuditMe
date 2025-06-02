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


def check_open_ports():


def check_admin_users():


def check_password_policy():


def check_auto_updates():


def check_insecure_services():


def check_ssh_config():


def check_disk_encryption():


def run_audits():
    checks = {
        "OS Version": check_os_version,
        "Firewall Status": check_firewall_status,
        "Antivirus Status": check_antivirus_status,
        "Open Ports": check_open_ports,
        "Admin/Sudo Users": check_admin_users,
        "Password Policy": check_password_policy,
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