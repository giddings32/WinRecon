# ![WinRecon Logo](assets/winrecon-logo.png)

## WinRecon

**WinRecon** is a PowerShell-based enumeration script designed to gather essential system information needed to identify potential privilege escalation opportunities on Windows machines. It automates the process of collecting valuable data to assist penetration testers, red teams, and system administrators in finding weaknesses that could lead to elevation of privileges.

---

## Features

- **System Information Collection**: Gathers key system details such as OS version, architecture, and hostname.
- **User and Group Enumeration**: Identifies all local users and groups, checking for any misconfigurations or privileged accounts that may be leveraged for escalation.
- **Installed Software & Vulnerabilities**: Detects installed software and versioning, helping to identify outdated or vulnerable applications.
- **Service Configuration Analysis**: Checks for misconfigured services, such as unquoted service paths or weak service permissions, that can be exploited.
- **File & Registry Permissions**: Identifies files and registry keys with weak permissions that could be exploited for privilege escalation.
- **Active Sessions & Historical Logins**: Scans for active sessions and recent login history to help identify potential paths for lateral movement or privilege escalation.
- **Automated Process**: Reduces the time and effort required for manual enumeration by automating data collection.

---

## Usage

1. **Upload** the `winrecon.ps1` script to the target Windows machine.
2. **Open PowerShell** with administrator privileges on the target machine.
3. Run the script with the following command:
   ```powershell
   .\winrecon.ps1
