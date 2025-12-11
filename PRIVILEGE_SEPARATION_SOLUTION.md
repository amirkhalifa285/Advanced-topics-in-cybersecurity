# Privilege Separation Solution (Section 2, Exercise 2.1)

## 1. Objective
The goal of this exercise is to mitigate the impact of a buffer overflow vulnerability in the `zookd` web server by implementing **Privilege Separation**.

**Original State:** `zookd` runs as a single monolithic process (often as root or the user). A vulnerability allows an attacker to execute arbitrary code with the server's full privileges (e.g., deleting sensitive files like `pass.txt`).

**New State:** The architecture is split into three components (`zookld`, `zookd`, `zooksvc`). The vulnerable component (`zookd`) now runs with low privileges (UID 6000). Even if compromised, it cannot harm the system.

## 2. Architecture Overview

We implemented the OKWS (Open Kernel Web Server) model:

1.  **`zookld` (Launcher Daemon)**
    *   **Role:** The "Supervisor".
    *   **Privileges:** Root (required to set UIDs and Chroot).
    *   **Tasks:**
        *   Creates IPC socket pair.
        *   Forks `zookd` (Dispatcher) and `zooksvc` (Service).
        *   **Sandboxing:** Uses `setuid`, `setgid`, and `chroot` to lock down children.
        *   **Keep-Alive:** Monitors child processes and restarts them if they crash.

2.  **`zookd` (Dispatcher)**
    *   **Role:** The "Front Door".
    *   **Privileges:** Low (UID 6000).
    *   **Tasks:**
        *   Listens on TCP port 8080.
        *   Parses headers (Contains the Vulnerability!).
        *   If safe, forwards the client socket + environment to `zooksvc` via `sendfd`.

3.  **`zooksvc` (Web Service)**
    *   **Role:** The "Worker".
    *   **Privileges:** Low (UID 6001) + **Chroot Jail**.
    *   **Tasks:**
        *   Receives socket from `zookd`.
        *   Executes the actual request logic (`http_serve`).
        *   Cannot access files outside the jail.

## 3. Implementation Details & Changes

### File: `zookld.c` (New)
*   **Logic:** Implements the supervisor loop.
*   **Key Syscalls:** `socketpair()`, `fork()`, `setresuid/gid()` (to drop privs), `chroot(".")` (to jail), `wait()` (to monitor).
*   **Fix for Dynamic Linking:** Includes a `setup_jail()` function that bind-mounts `/lib`, `/lib64`, and `/usr` into the jail so the dynamic linker (`ld-linux`) works for `zooksvc`.

### File: `zooksvc.c` (New)
*   **Logic:** Worker loop.
*   **IPC:** Uses `recvfd()` (from `http.c`) to receive the client connection from `zookd`.
*   **Environment:** Reconstructs request state using `env_deserialize()`.

### File: `zookd.c` (Modified)
*   **Logic:** Changed `process_client` to **stop** after header parsing.
*   **IPC:** Instead of calling `http_serve` directly, it packages the environment (`env_serialize`) and passes the baton to `zooksvc` using `sendfd()`.
*   **Startup:** Accepts the control socket FD as a command-line argument.

### File: `Makefile` (Modified)
*   Added rules to build `zookld` and `zooksvc`.
*   Linked `zooksvc` with `http.o` (since it needs server logic) but `zookld` stands alone.

## 4. Demonstration Guide (How to Present)

Follow these steps to demonstrate the solution in class.

### Step 1: Setup & Compile
Ensure the environment is clean and the code is compiled.
```bash
cd ~/Desktop/Advanced_cyber/lab/lab
make clean && make
```

### Step 2: Create the "Secret" File
Create the file that the attacker wants to destroy.
```bash
echo "This is a secret file." > pass.txt
ls -l pass.txt
# Output should show it exists.
```

### Step 3: Start the Secure Server
Run the launcher daemon with `sudo` (required for privilege separation).
```bash
sudo ./zookld
```
*   **Output:** You will see "Launching zookd..." and "Launching zooksvc...".
*   **Note:** If you see errors about "mount", it might be because previous mounts persist. It usually ignores them safely.

### Step 4: Run the Attack (in a new terminal)
Run the exploit script. This sends a malicious payload designed to crash the server and execute shellcode to unlink `pass.txt`.

```bash
cd ~/Desktop/Advanced_cyber/lab/lab
./exploit-2.py localhost 8080
```
*   **Expected Output:**
    *   Exploit script: `[!] Connection error... Server likely crashed!`
    *   Server terminal: `zookld: zookd (pid X) died, restarting`.

### Step 5: Verify Protection
Check if the attack succeeded.
```bash
ls -l pass.txt
```
*   **Result:** The file `pass.txt` **MUST still exist**.
*   **Why?** The exploit successfully crashed `zookd`, but because `zookd` was running as `UID 6000`, the OS denied the `unlink("pass.txt")` syscall (since `pass.txt` is owned by your user/root).

### Step 6: Cleanup
Stop the server.
```bash
sudo killall zookld zookd zooksvc
```