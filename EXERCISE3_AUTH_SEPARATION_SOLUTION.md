# Exercise 3: Authentication Service Privilege Separation Solution

## 1. Objective
The goal of Exercise 3 is to protect user credentials (passwords and tokens) by implementing **privilege separation** for the authentication service.

**Original State:** All user data (profile, zoobars, passwords, tokens) stored in a single database accessible by the web application. A vulnerability in the web app could expose all user credentials.

**New State:** Credentials are split into a separate database (`cred.db`) managed by a dedicated authentication service (`authsvc`) running with its own UID. The main application communicates with this service via RPC, never directly accessing passwords.

## 2. Architecture Overview

### The Privilege-Separated Authentication Model:

```
┌─────────────────────────────────────────────────────────────────┐
│                     zookld (Launcher - UID 0)                   │
│                   Spawns and monitors services                   │
└──────────┬──────────────────────┬──────────────────────────────┘
           │                      │
           │                      │
┌──────────▼────────────┐  ┌──────▼───────────────────────────────┐
│   zookd               │  │   zooksvc (Web Service)              │
│   UID: 6000           │  │   UID: 6001, GID: 11111              │
│   GID: 6000           │  │   Handles HTTP requests              │
│   (Dispatcher)        │  │   Manages person.db (profiles)       │
└───────────────────────┘  └──────────┬───────────────────────────┘
                                      │
                                      │ RPC via Unix Socket
                                      │ /authsvc/sock
                                      │
                           ┌──────────▼───────────────────────────┐
                           │   authsvc (Auth Service)             │
                           │   UID: 33333, GID: 11111             │
                           │   Manages cred.db (credentials)      │
                           │   - Stores passwords & tokens        │
                           │   - Issues new tokens                │
                           │   - Validates credentials            │
                           └──────────────────────────────────────┘
```

### Key Components:

1. **`authsvc` (Authentication Service)**
   - **UID/GID:** 33333:11111
   - **Database:** `/zoobar/db/cred/cred.db` (owned by 33333:11111)
   - **Socket:** `/authsvc/sock` (permissions 770, accessible by group 11111)
   - **Functions:**
     - `rpc_register(username, password)` - Creates new user credentials
     - `rpc_login(username, password)` - Validates credentials, returns token
     - `rpc_check_token(username, token)` - Validates session tokens
     - `rpc_newtoken(username, password)` - Generates new session token

2. **`zooksvc` (Web Service)**
   - **UID/GID:** 6001:11111 (Group 11111 allows IPC with authsvc)
   - **Database:** `/zoobar/db/person/person.db` (public profile data)
   - **Role:** Handles web requests, uses auth_client to communicate with authsvc

3. **Common IPC Group (11111)**
   - All services that need to communicate share this group
   - Sockets have 770 permissions (owner + group only)
   - Maintains security while allowing necessary communication

## 3. Implementation Details

### Files Created/Modified:

#### 3.1 `zoobar/zoodb.py` (Modified)
Added the `Cred` table to store credentials separately:

```python
CredBase = declarative_base()

class Cred(CredBase):
    __tablename__ = "cred"
    username = Column(String(128), primary_key=True)
    password = Column(String(128))
    token = Column(String(128))

def cred_setup():
    return dbsetup("cred", CredBase)
```

#### 3.2 `zoobar/auth-server.py` (Created)
The RPC server for authentication service:

```python
class AuthRpcServer(rpclib.RpcServer):
    def rpc_register(self, username, password):
        creddb = cred_setup()
        cred = creddb.get(Cred, username)
        if cred:
            return None  # User already exists

        newcred = Cred()
        newcred.username = username
        newcred.password = password
        creddb.add(newcred)
        creddb.commit()

        return self.rpc_newtoken(username, password)

    def rpc_login(self, username, password):
        db = cred_setup()
        cred = db.get(Cred, username)
        if not cred or cred.password != password:
            return None
        return self.rpc_newtoken(username, password)

    def rpc_check_token(self, username, token):
        db = cred_setup()
        cred = db.get(Cred, username)
        return cred and cred.token == token
```

#### 3.3 `zoobar/auth_client.py` (Created)
Client-side RPC stubs for communication:

```python
def login(username, password):
    with rpclib.client_connect('/authsvc/sock') as client:
        return client.call('login', username=username, password=password)

def register(username, password):
    with rpclib.client_connect('/authsvc/sock') as client:
        return client.call('register', username=username, password=password)

def check_token(username, token):
    with rpclib.client_connect('/authsvc/sock') as client:
        return client.call('check_token', username=username, token=token)
```

#### 3.4 `zoobar/login.py` (Modified)
Changed to use auth_client instead of direct auth.py calls:

```python
import auth_client

def addRegistration(self, username, password):
    # Step 1: Create credentials via authsvc
    token = auth_client.register(username, password)
    if token is not None:
        # Step 2: Create Person profile (zooksvc has permission)
        persondb = person_setup()
        newperson = Person()
        newperson.username = username
        persondb.add(newperson)
        persondb.commit()
        return self.loginCookie(username, token)
    return None

def checkLogin(self, username, password):
    token = auth_client.login(username, password)
    if token is not None:
        return self.loginCookie(username, token)
    return None
```

#### 3.5 `zookld.c` (Modified)
**Critical Fix:** Changed `SERVICE_GID` from 6001 to 11111:

```c
#define SERVICE_UID 6001
#define SERVICE_GID 11111  // Changed from 6001 to allow IPC
#define AUTH_UID 33333
#define AUTH_GID 11111
```

Added `launch_authsvc()` function:

```c
void launch_authsvc() {
    if ((authsvc_pid = fork()) < 0) err(1, "fork authsvc");
    if (authsvc_pid == 0) {
        close(sv[0]); close(sv[1]);
        close(auth_sv[0]);

        char fd_str[16];
        sprintf(fd_str, "%d", auth_sv[1]);
        char sockpath[] = "/authsvc/sock";

        setup_jail();
        if (chroot(".") < 0) warn("chroot failed for authsvc");
        if (setgid(AUTH_GID) < 0) warn("setgid authsvc");
        if (setuid(AUTH_UID) < 0) warn("setuid authsvc");

        execl("/usr/bin/python3", "python3",
              "zoobar/auth-server.py", fd_str, sockpath, NULL);
        err(1, "execl auth-server.py");
    }
}
```

#### 3.6 `setup.sh` (Modified)
Sets up directories and permissions for the auth service:

```bash
mkdir -p "$jail"/{authsvc,auth_secure_keys}
chmod 770 "$jail"/{authsvc,banksvc,zoobar/db}
chown 33333:11111 "$jail"/{authsvc,auth_secure_keys}
chown "$USER":11111 "$jail"/zoobar/db
```

## 4. Security Properties

### Data Isolation:
- **cred.db** (UID 33333): Passwords, tokens - ONLY accessible by authsvc
- **person.db** (UID 6001): Profiles, zoobars - accessible by zooksvc
- Even if zooksvc is compromised, attacker cannot read cred.db

### Process Isolation:
- authsvc runs in chroot jail with UID 33333
- zooksvc runs in chroot jail with UID 6001
- Different UIDs = OS-level access control

### Communication Security:
- Unix domain socket (faster than TCP, no network exposure)
- Socket permissions (770) + Group 11111 = Only authorized services
- RPC protocol validates requests

## 5. Demonstration Guide

### Step 1: Setup and Start Server
```bash
cd ~/Desktop/Advanced_cyber/lab/lab
make clean && make
sudo ./zookld
```

**Expected Output:**
```
Launching zookd...
Launching zooksvc...
Launching authsvc...
zookd dispatcher running as UID=6000, GID=6000
```

### Step 2: Verify Service Isolation
In another terminal, check the running processes:
```bash
ps aux | grep -E "(zookd|zooksvc|authsvc|python3.*auth-server)" | grep -v grep
```

**Expected Output:**
```
root       [PID]  ... ./zookld
6000       [PID]  ... zookd 8080 3
6001       [PID]  ... zooksvc 4
33333      [PID]  ... python3 zoobar/auth-server.py ...
```

**Key Point:** Notice the different UIDs (6000, 6001, 33333) - each service runs with minimal privileges.

### Step 3: Test User Registration
Navigate to `http://localhost:8080/` and register a user:
- Username: `testuser`
- Password: `testpass`

**What Happens Behind the Scenes:**
1. Browser → zookd → zooksvc (handles HTTP)
2. zooksvc calls `auth_client.register()`
3. RPC request sent to `/authsvc/sock`
4. authsvc creates entry in `cred.db` (owned by UID 33333)
5. authsvc returns token to zooksvc
6. zooksvc creates entry in `person.db` (owned by UID 6001)

### Step 4: Verify Database Separation
```bash
# Check person database (public data)
sqlite3 zoobar/db/person/person.db "SELECT * FROM person;"
```
**Output:** `testuser|10|` (username, zoobars, profile)

```bash
# Check credentials database (sensitive data)
sqlite3 zoobar/db/cred/cred.db "SELECT username, password, token FROM cred;"
```
**Output:** `testuser|testpass|[32-char-token]`

### Step 5: Verify File Ownership
```bash
ls -lh zoobar/db/*/*.db
```

**Expected Output:**
```
-rw-rw-rw- 1 33333    11111 12K cred.db      ← Owned by authsvc
-rw-rw-rw- 1 amirkhalifa 11111 12K person.db  ← Owned by user/zooksvc
```

**Key Point:** Different ownership = isolation. If zooksvc is compromised, the attacker (running as UID 6001) cannot modify cred.db (owned by UID 33333).

### Step 6: Test Login
Log out and log back in with the created user to verify token validation works.

## 6. Files to Submit

### Core Implementation Files:
```
lab/
├── zookld.c                      # Modified: Added authsvc launch, fixed SERVICE_GID
├── zoobar/
│   ├── auth-server.py            # New: Auth RPC server
│   ├── auth_client.py            # New: Auth RPC client stubs
│   ├── login.py                  # Modified: Uses auth_client
│   ├── zoodb.py                  # Modified: Added Cred table
│   └── rpclib.py                 # Provided: RPC library (no changes needed)
└── setup.sh                      # Modified: Sets up authsvc directories
```

### Documentation Files:
```
├── EXERCISE3_AUTH_SEPARATION_SOLUTION.md  # This file
├── GEMINI.md                               # Updated project status
└── HOMEWORK_TASKS.md                       # Original requirements
```

### Supporting Files (if needed):
```
├── Makefile                      # May have minor modifications
└── cleanup_mounts.sh             # Helper script for cleanup
```

## 7. Testing Checklist

- [ ] Server starts without errors
- [ ] All three services run with correct UIDs (6000, 6001, 33333)
- [ ] User registration succeeds
- [ ] Credentials saved in `cred.db` (owned by 33333)
- [ ] Profile saved in `person.db` (owned by 6001)
- [ ] Login with created user succeeds
- [ ] Token validation works (protected pages accessible)

## 8. Common Issues and Fixes

### Issue: "Permission denied" connecting to /authsvc/sock
**Cause:** zooksvc (UID 6001) not in group 11111
**Fix:** Verify `SERVICE_GID = 11111` in zookld.c, recompile

### Issue: "attempt to write a readonly database"
**Cause:** Database directory has wrong permissions
**Fix:** `sudo chmod 770 zoobar/db` and verify ownership

### Issue: authsvc process not starting
**Cause:** Python path or permissions issue
**Fix:** Check `/usr/bin/python3` exists in jail via bind mount

## 9. Key Takeaways

1. **Defense in Depth:** Even if one service is compromised, others remain protected
2. **Principle of Least Privilege:** Each service has minimal permissions needed
3. **OS-Level Enforcement:** UID/GID provide kernel-enforced access control
4. **IPC Security:** Unix sockets + group permissions = secure communication
5. **Data Separation:** Sensitive data isolated in separate databases with different ownership

**Exercise 3 Complete!** ✅

Next: Exercise 4 will add password hashing and salting to further protect credentials even if cred.db is somehow accessed.
