# Exercise 1 Documentation - Complete Package

## Overview
This package contains comprehensive documentation for **Section 1, Buffer Overflow Exercise 1** of the Advanced Topics in Cyber System Security project.

---

## Documents Created

### 📄 1. BUFFER_OVERFLOW_ANALYSIS.md
**Purpose:** Complete technical analysis of the vulnerability  
**Use:** Deep dive reference, complete understanding  
**Length:** ~515 lines  
**Contains:**
- Full application architecture diagram
- Detailed vulnerability analysis
- Stack memory layout diagrams
- Exploitation techniques
- Step-by-step exploit construction
- Additional vulnerabilities found
- Code examples in Python

**Best for:** Understanding the technical details, writing your report

---

### 📄 2. EXERCISE1_SUMMARY.md  
**Purpose:** Quick reference guide for presentations  
**Use:** Cheat sheet during demo  
**Length:** ~109 lines  
**Contains:**
- Quick vulnerability summary
- Call stack visualization
- Exploitation steps
- GDB commands
- Defense mechanisms
- Clean, concise format

**Best for:** Quick review before class, presentation notes

---

### 📄 3. STACK_DIAGRAM.txt
**Purpose:** Visual representation of stack memory  
**Use:** Show during presentation on screen  
**Length:** ~128 lines  
**Contains:**
- ASCII art stack layout
- Memory addresses with annotations
- Distance calculations
- Exploit payload structure
- Before/after memory states
- Key insights summary

**Best for:** Visual learners, explaining to classmates, presentations

---

### 📄 4. DEMONSTRATION_GUIDE.md
**Purpose:** Step-by-step demo script  
**Use:** Follow during live demonstration  
**Length:** ~394 lines  
**Contains:**
- Preparation checklist
- Time-stamped sections (5-10 min each)
- Exact commands to run
- Terminal-by-terminal instructions
- GDB session walkthrough
- Q&A preparation
- Troubleshooting tips
- Time management guide

**Best for:** Live demonstrations, practice sessions, ensuring nothing is forgotten

---

### 📄 5. README_EXERCISE1.md (this file)
**Purpose:** Navigation and overview  
**Use:** Starting point for all documentation  
**Contains:**
- Document descriptions
- Quick facts
- Key findings summary
- Usage recommendations

---

## Quick Facts

### Exercise 1: Vulnerability Analysis
**Three vulnerabilities identified:**
1. `url_decode()` - NO bounds check (reqpath[4096] buffer)
2. `http_serve()` - Off-by-one error (pn[2048] buffer)
3. `dir_join()` - Unsafe strcpy/strcat

### Exercise 2: Successful Exploitation ✅
- **Exploited:** `url_decode()` vulnerability
- **File:** `http.c`, lines 441-471
- **Function:** `url_decode(char *dst, const char *src)`
- **Target Buffer:** `reqpath[4096]` in `process_client()` (zookd.c line 103)
- **Bug Type:** NO bounds checking on destination
- **Exploit:** Send 8000 bytes → overflow 4096-byte buffer → crash!

### The Numbers (Your System)
- **Current Directory:** `/home/amirkhalifa/Desktop/Advanced_cyber/lab/lab`
- **CWD Length:** 48 bytes (plus 1 for newline = 49)
- **Buffer Size:** 2048 bytes
- **Distance to Saved RIP:** ~2088 bytes (verify with gdb)
- **Offset for Exploit:** 2088 - 48 = 2040 bytes

### The Attack Vector
```http
GET /[2040_bytes_payload][8_bytes_rbp][8_bytes_rip] HTTP/1.0
```

### The Call Stack
```
main() → run_server() → accept() → fork() → 
process_client() → http_request_line() → 
http_request_headers() → http_serve() [VULNERABLE]
```

---

## How to Use These Documents

### For Learning & Understanding
1. Start with **BUFFER_OVERFLOW_ANALYSIS.md** - Read sections 1-3
2. Review **STACK_DIAGRAM.txt** - Visualize the memory
3. Read **EXERCISE1_SUMMARY.md** - Solidify understanding

### For Practicing the Demo
1. Read **DEMONSTRATION_GUIDE.md** completely
2. Open 3 terminal windows as described
3. Follow step-by-step, practice each section
4. Time yourself for each part
5. Practice at least twice before the actual presentation

### For the Presentation
1. Have **EXERCISE1_SUMMARY.md** open on one screen
2. Have **DEMONSTRATION_GUIDE.md** open for reference
3. Display **STACK_DIAGRAM.txt** when explaining memory
4. Keep terminals ready as per the guide

### For Writing Your Report
1. Use **BUFFER_OVERFLOW_ANALYSIS.md** as your source
2. Include the architecture diagram
3. Add the stack diagram
4. Reference the call stack
5. Cite the additional vulnerabilities found

---

## Key Findings Summary

### Primary Vulnerability
**http_serve() Buffer Overflow**
- Stack-based buffer overflow in `pn[2048]`
- Caused by incorrect length check (`>=` instead of `>`)
- Allows attacker to overwrite saved return address
- Controllable via HTTP GET request URL path
- Can achieve arbitrary code execution

### Additional Vulnerabilities

**1. dir_join() - HIGH RISK**
- Uses `strcpy()` and `strcat()` without bounds checking
- Located in http.c, lines 347-352
- Exploitable through directory traversal attacks

**2. url_decode() - MEDIUM RISK**
- No bounds checking on destination buffer
- Located in http.c, lines 441-471
- Depends on caller to ensure sufficient space

### Attack Impact
- **Denial of Service:** Crash the web server
- **Code Execution:** Run arbitrary shellcode
- **System Compromise:** Delete files, steal data, install backdoors
- **Remote Attack:** No authentication required

### Defense Recommendations
1. Fix the length check: use `>` instead of `>=`
2. Replace `strncat()` with `snprintf()`
3. Enable stack canaries (remove `-fno-stack-protector`)
4. Enable ASLR system-wide
5. Use non-executable stack (DEP/NX)
6. Implement input validation and sanitization
7. Add logging and intrusion detection

---

## Commands Quick Reference

### Start the Server
```bash
./zookd 8080 &
```

### Test Normal Operation
```bash
curl http://localhost:8080/
```

### Debug with GDB
```bash
gdb -p $(pgrep zookd)
(gdb) set follow-fork-mode child
(gdb) break http_serve
(gdb) continue
# In another terminal: curl http://localhost:8080/test
(gdb) print &pn
(gdb) info frame
```

### Crash the Server
```bash
python3 -c "print('GET /' + 'A'*3000 + ' HTTP/1.0\r\n\r\n')" | nc localhost 8080
dmesg | tail
```

### Check for Crashes
```bash
# Check process status
ps aux | grep zookd

# Check kernel logs
dmesg | tail -10

# Check parent process output
# Should see: "Child process XXXX terminated incorrectly, receiving signal 11"
```

---

## Presentation Tips

### Opening (2 minutes)
- Introduce yourself
- State the objective: "Find a buffer overflow vulnerability in zookd web server"
- Preview what you'll show

### Middle (25-30 minutes)
- Show architecture (5 min)
- Identify vulnerability (10 min)
- GDB session (10 min)
- Crash demonstration (5 min)

### Closing (5 minutes)
- Impact discussion
- Mitigation strategies
- Open for questions

### During Demo
- **Speak clearly** - Explain what you're doing
- **Go slowly** - Let commands finish before moving on
- **Engage audience** - Ask if they have questions
- **Handle errors gracefully** - Have backup plans

### If Something Goes Wrong
- Stay calm
- Explain what should have happened
- Show the expected output from screenshots/documentation
- Move on to next section

---

## Practice Checklist

Before your presentation, make sure you can:

- [ ] Explain what a buffer overflow is in simple terms
- [ ] Show the vulnerable code and explain the bug
- [ ] Start the server successfully
- [ ] Attach gdb and set breakpoints
- [ ] Find the pn[] buffer address
- [ ] Find the saved RIP address
- [ ] Calculate the offset correctly
- [ ] Crash the server with a long request
- [ ] Explain the stack diagram
- [ ] Discuss the impact
- [ ] Suggest mitigations
- [ ] Answer "Why is this dangerous?"
- [ ] Answer "How would you fix it?"

---

## Additional Resources

### Project Documents
- `Advanced topics is cyber system security project.md` - Original assignment
- `exploit-template.py` - Provided exploit template
- `zookd.c` - Main server source
- `http.c` - HTTP handling source (contains vulnerability)

### External Resources
- "Smashing the Stack in the 21st Century" - Understanding buffer overflows
- GDB documentation - Debugging reference
- x86-64 calling convention - Stack layout understanding

---

## Next Steps (After Exercise 1)

Once you've mastered Exercise 1:

**Exercise 2:** Write exploit-2.py to actually crash the server  
**Exercise 3:** Modify shellcode.S to unlink password.txt  
**Exercise 4:** Combine shellcode with exploit for full attack  

---

## Support & Questions

If you have questions:
1. Review the appropriate document above
2. Check the troubleshooting section in DEMONSTRATION_GUIDE.md
3. Practice the demo again
4. Consult with classmates or instructor

---

## Document Version
- **Created:** November 9, 2025
- **Last Updated:** November 9, 2025
- **Author:** Analysis by AI Assistant for Amir Khalifa
- **Exercise:** Section 1, Buffer Overflow Exercise 1

---

**Good luck with your demonstration! You've got this! 🚀**
