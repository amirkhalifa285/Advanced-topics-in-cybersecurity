# Buffer Overflow Vulnerability Analysis - Exercise 1
## Advanced Topics in Cyber System Security

**Student:** Amir Khalifa  322393760
**Lab:** Section 1 - Buffer Overflow Exercise 1

---

## 1. Application Architecture

### Process Flow Diagram
```
┌─────────────────────────────────────────────────────────────┐
│                        zookd (main)                          │
│                     Port: 8080 (default)                     │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  start_server() │
                    │  - socket()     │
                    │  - bind()       │
                    │  - listen()     │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  run_server()   │
                    │  - accept()     │
                    │  - fork()       │
                    └────────┬────────┘
                             │
                   ┌─────────┴──────────┐
                   │                    │
            Parent Process         Child Process
            (closes client)        (handles request)
                   │                    │
                   │                    ▼
                   │           ┌─────────────────┐
                   │           │ process_client()│
                   │           └────────┬────────┘
                   │                    │
                   │                    ▼
                   │        ┌────────────────────────┐
                   │        │ http_request_line()    │
                   │        │ - Parse GET/POST       │
                   │        │ - url_decode()         │
                   │        └────────┬───────────────┘
                   │                 │
                   │                 ▼
                   │        ┌────────────────────────┐
                   │        │ http_request_headers() │
                   │        │ - Parse headers        │
                   │        │ - url_decode()         │
                   │        └────────┬───────────────┘
                   │                 │
                   │                 ▼
                   │        ┌────────────────────────┐
                   │        │    http_serve()        │
                   │        │  *** VULNERABLE ***    │
                   │        └────────┬───────────────┘
                   │                 │
                   │        ┌────────┴────────┐
                   │        │                 │
                   │        ▼                 ▼
                   │  http_serve_file()  http_serve_executable()
                   │  http_serve_dir()   http_serve_none()
                   │
                   └──► wait() & cleanup
```

### Key Components

1. **zookd.c - Main Daemon**
   - Accepts incoming HTTP connections on specified port
   - Forks a new child process for each client connection
   - Parent waits for child and reports crashes (signal 11 = SIGSEGV)

2. **http.c - HTTP Request Handling**
   - Parses HTTP request lines and headers
   - Serves static files, directories, and CGI scripts
   - Contains vulnerable buffer operations

### Thread/Process Model
- **Main Process**: Listens on socket, accepts connections
- **Child Processes**: One per client connection (forked)
- **No threads**: Traditional Unix fork model

### Static vs Dynamic Page Loading

**Static Pages:**
- Served via `http_serve_file()`
- Direct file reading and `sendfile()` to client
- No execution, just content delivery

**Dynamic Pages (CGI):**
- Served via `http_serve_executable()`
- Fork/exec model: creates subprocess
- Executes script with environment variables
- Output captured via pipe and sent to client

---

## 2. Vulnerability Discovery

### Methodology
I analyzed the C code looking for:
1. Stack-allocated buffers (local arrays)
2. Unsafe string operations (strcpy, strcat, sprintf)
3. Missing bounds checking
4. User-controlled input reaching vulnerable functions

### THREE Vulnerabilities Found:

---

### Vulnerability #1: `url_decode()` Function ⭐ EXPLOITED IN EXERCISE 2

**Location:** `http.c`, lines 441-471  
**Called from:** `http_request_line()` at line 105  
**Target buffer:** `reqpath[4096]` in `process_client()` (zookd.c, line 103)

#### Vulnerable Code:
```c
// In zookd.c, process_client():
static void process_client(int fd)
{
    static char env[8192];
    static size_t env_len = 8192;
    char reqpath[4096];  // ← VULNERABLE BUFFER (4096 bytes, on STACK)
    const char *errmsg;

    if ((errmsg = http_request_line(fd, reqpath, env, &env_len)))
        return http_err(fd, 500, "http_request_line: %s", errmsg);
    // ...
}

// In http.c, http_request_line():
url_decode(reqpath, sp1);  // ← NO BOUNDS CHECK!

// In http.c, url_decode():
void url_decode(char *dst, const char *src)
{
    for (;;)
    {
        // ... URL decoding logic ...
        *dst = *src;  // ← NO BOUNDS CHECK ON dst!
        dst++;
        // Keeps writing until src ends!
    }
}
```

**Why This is Critical:**
- **NO length check** before calling `url_decode()`
- `url_decode()` has **NO bounds checking** on destination
- Attacker can send URL > 4096 bytes
- Overflows `reqpath` buffer on stack
- **This is what exploit-2.py exploits!**

---

### Vulnerability #2: `http_serve()` Function

**Location:** `http.c`, lines 273-301  
**Function:** `http_serve(int fd, const char *name)`  
**Target buffer:** `pn[2048]` (stack-allocated)

#### Vulnerable Code:
```c
void http_serve(int fd, const char *name)
{
    void (*handler)(int, const char *) = http_serve_none;
    char pn[2048];              // ← VULNERABLE BUFFER (2048 bytes)
    struct stat st;

    getcwd(pn, sizeof(pn));
    setenv("DOCUMENT_ROOT", pn, 1);

    if (strlen(name) + strlen(pn) + 1 >= sizeof(pn)) {
        http_err(fd, 500, "Request too long");
        return;
    }
    strncat(pn, name, sizeof(pn) - strlen(pn) - 1);  // ← DANGEROUS!
    split_path(pn);
    // ... rest of function
}
```

**Why This is Difficult to Exploit:**
- Length check limits input to ~1997 bytes
- With CWD of 48 bytes, total = 2045 bytes
- Saved RIP is at offset 2088 bytes from buffer start
- **Cannot reach RIP** with this vulnerability alone (43 bytes short!)
- Off-by-one error exists but insufficient for full exploitation

---

## 3. Detailed Vulnerability Analysis

### The Vulnerable Buffer: `pn[2048]`

**Type:** Stack-allocated character array  
**Size:** 2048 bytes  
**Location:** Local variable in `http_serve()`

### Why This Is Vulnerable

#### The Check That Fails
```c
if (strlen(name) + strlen(pn) + 1 >= sizeof(pn)) {
    http_err(fd, 500, "Request too long");
    return;
}
```

**Problem:** This check uses `>=` instead of `>`

**What this means:**
- If `strlen(name) + strlen(pn) + 1 == sizeof(pn)` (exactly 2048), the check passes!
- The subsequent `strncat()` will then write 2048 bytes into a 2048-byte buffer
- This overwrites the null terminator and can overflow into adjacent stack memory

#### The Unsafe Operation
```c
strncat(pn, name, sizeof(pn) - strlen(pn) - 1);
```

**Problems:**
1. `strncat()` appends `n` characters PLUS a null terminator
2. The third parameter calculation can be wrong if the check allows edge cases
3. Even if the check were correct, `strncat()` is notoriously error-prone

### Call Stack to Vulnerability

```
main()
  └─→ run_server()
       └─→ accept()
            └─→ fork()
                 └─→ [CHILD PROCESS]
                      └─→ process_client(cltfd)
                           └─→ http_request_line(fd, reqpath, env, &env_len)
                                └─→ url_decode(reqpath, sp1)  [decodes URL]
                           └─→ http_request_headers(fd)
                           └─→ http_serve(fd, getenv("REQUEST_URI"))
                                     *** VULNERABILITY TRIGGERED HERE ***
```

### Attack Vector: HTTP Request Path

The attacker controls the `name` parameter through the HTTP request:

**Example HTTP Request:**
```http
GET /AAAA...AAAA HTTP/1.0

```

Where `AAAA...AAAA` is a carefully crafted string that:
1. Passes the length check (edge case)
2. Overflows `pn[]` buffer
3. Overwrites saved return address on stack

### What Gets Overwritten

When `pn[]` overflows, it can overwrite:
1. Other local variables (e.g., `st` struct)
2. Saved frame pointer (saved `%rbp`)
3. **Saved return address (saved `%rip`)** ← TARGET
4. Function arguments from caller
5. Potentially more stack data

---

## 4. Stack Diagram

### Stack Layout for `http_serve()` Function

```
High Memory Addresses (e.g., 0x7fffffffdcd0)
┌────────────────────────────────────────┐
│   Return Address to process_client()   │ ← Saved %rip (8 bytes)
│   (0x7fffffffdcc8)                     │   *** TARGET FOR EXPLOIT ***
├────────────────────────────────────────┤
│   Saved Frame Pointer                  │ ← Saved %rbp (8 bytes)
│   (0x7fffffffdcc0)                     │
├────────────────────────────────────────┤
│   Saved %rbx register                  │ ← (8 bytes)
│   (0x7fffffffdcb8)                     │
├────────────────────────────────────────┤
│                                        │
│   struct stat st                       │ ← ~144 bytes (platform dependent)
│   (stores file metadata)               │
│                                        │
├────────────────────────────────────────┤
│                                        │
│   char pn[2048]                        │ ← VULNERABLE BUFFER (2048 bytes)
│   (0x7fffffffd4a0)                     │   Starts here
│                                        │
│   [0]   [1]   [2]  ...  [2047]        │
│                                        │
│   Initially contains: getcwd() result  │
│   Then concatenated with: name param   │
│                                        │
├────────────────────────────────────────┤
│   Function pointer: handler            │ ← 8 bytes
│   (points to http_serve_none)          │
├────────────────────────────────────────┤
│   Parameter: const char *name          │ ← 8 bytes (pointer)
├────────────────────────────────────────┤
│   Parameter: int fd                    │ ← 4 bytes
└────────────────────────────────────────┘
Low Memory Addresses (stack grows down)
```

### Key Distances (Example from gdb session)

Based on the project document's gdb example:
- `pn[]` buffer starts at: `0x7fffffffd4a0`
- Saved `%rip` (return address) at: `0x7fffffffdcc8`
- **Distance:** `0x7fffffffdcc8 - 0x7fffffffd4a0 = 0x828` = **2088 bytes**

**To overwrite return address:**
- Need to write 2088 bytes of padding
- Then write 8 bytes of new return address (little-endian on x86-64)

### Memory Layout During Overflow

```
Before overflow:
pn[2048]:  [/home/user/lab/][\0][unused space........][st struct][rbp][rip]

During overflow with payload:
pn[2048]:  [AAAAAAAAAA...AAAA][BBBB...BBBB][CCCCCCCC][0xdeadbeef]
           └─ 2088 'A's ─────┘ └─padding──┘ └─rbp──┘ └─new rip─┘
                                                        (shellcode address)
```

---


---


---

## 7. Exercise 2: Successful Exploitation

### Which Vulnerability We Exploited

**Target:** Vulnerability #1 - `url_decode()` in `process_client()`  
**Exploit File:** `exploit-2.py`  
**Result:** Server crash with signal 11 (SIGSEGV)

### Why url_decode() Instead of http_serve()?

**Attempted First:** `http_serve()` vulnerability (pn[2048] buffer)
- Problem: Length check prevents reaching saved RIP
- Maximum payload: 1997 bytes
- Distance to RIP: 2088 bytes  
- **Gap: 91 bytes short!**

**Successful Exploit:** `url_decode()` vulnerability (reqpath[4096] buffer)
- **No length check!**
- Can send unlimited data
- Sent 8000 bytes into 4096-byte buffer
- **4000-byte overflow guaranteed to corrupt stack!**

### Exploit Strategy

```python
payload_size = 8000
payload = b"A" * payload_size
request = b"GET /" + payload + b" HTTP/1.0\r\n\r\n"
```

**What happens:**
1. Client sends HTTP request with 8000 'A' characters in URL path
2. `process_client()` receives request, declares `char reqpath[4096]` on stack
3. Calls `http_request_line(fd, reqpath, ...)`
4. `http_request_line()` calls `url_decode(reqpath, url_path)`  
5. `url_decode()` writes all 8000 bytes into 4096-byte buffer
6. Stack overflow corrupts:
   - Local variables
   - Saved frame pointer (RBP)
   - Saved return address (RIP)
7. When function tries to return → **CRASH!**

### Evidence of Success

**Terminal output:**
```
Child process 181041 terminated incorrectly, receiving signal 11
```

**dmesg kernel log:**
```
traps: zookd[181041] general protection fault ip:7f5e27d48f9c 
sp:7ffc21961ed8 error:0 in libc.so.6
```

