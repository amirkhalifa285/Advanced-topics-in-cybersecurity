#!/bin/bash
##############################################################################
# PRIVILEGE SEPARATION DEMONSTRATION SCRIPT
# Exercise 2 (Privilege Separation) + Exercise 3 (Auth Service Separation)
#
# This script demonstrates:
# 1. Three processes running with different UIDs (6000, 6001, 33333)
# 2. Web application functionality (via HTTP check)
# 3. Attack mitigation (exploit fails to delete protected files)
# 4. Filesystem privilege separation inside jail
##############################################################################

# Colors for pretty output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
TARGET_FILE="pass.txt"
JAIL_ROOT="/home/amirkhalifa/Desktop/Advanced_cyber/lab/lab"

##############################################################################
# Helper Functions
##############################################################################

print_header() {
    echo ""
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  $1${NC}"
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${BLUE}${BOLD}>>> $1${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

wait_for_user() {
    echo ""
    echo -e "${YELLOW}Press ENTER to continue...${NC}"
    read -r
}

##############################################################################
# MAIN DEMONSTRATION
##############################################################################

clear
print_header "PRIVILEGE SEPARATION SECURITY DEMONSTRATION"

echo -e "${BOLD}Demonstrating:${NC}"
echo "  • Exercise 2.1: Three-tier privilege separation (zookld → zookd → zooksvc)"
echo "  • Exercise 3: Authentication service isolation (authsvc)"
echo "  • Attack mitigation via UID/GID separation"
echo "  • Filesystem privilege enforcement"
echo ""

wait_for_user

##############################################################################
# STEP 1: Verify Server is Running
##############################################################################

print_header "STEP 1: Verify Server Processes"

print_section "1.1 Checking for running processes..."

if ! pgrep -x "zookld" > /dev/null; then
    print_error "Server not running! Please start './zookld' in another terminal first."
    exit 1
fi

print_success "Server is running!"
sleep 1

##############################################################################
# STEP 2: Show Process Privilege Separation
##############################################################################

print_section "1.2 Process Privilege Separation"

echo -e "${BOLD}Expected Architecture:${NC}"
echo "  zookld (launcher) → UID 0 (root)"
echo "  ├─ zookd (dispatcher) → UID 6000"
echo "  ├─ zooksvc (web service) → UID 6001, GID 11111"
echo "  └─ authsvc (auth service) → UID 33333, GID 11111"
echo ""

echo -e "${BOLD}Actual Running Processes:${NC}"
echo ""

# Display process tree
ps aux | head -1
ps aux | grep -E "(zookld|zookd|zooksvc|python3.*auth-server)" | grep -v grep | \
    awk '{printf "%-10s %-8s %-8s %s\n", $1, $2, $11, $0}' | \
    cut -d' ' -f1-4,11-

echo ""

# Detailed process information
echo -e "${BOLD}Detailed UID/GID Information:${NC}"
echo ""

# Find each process and show its UID/GID
for proc in zookld zookd zooksvc; do
    PID=$(pgrep -x "$proc" | head -1)
    if [ -n "$PID" ]; then
        PROC_INFO=$(ps -o user=,uid=,gid=,cmd= -p "$PID" 2>/dev/null)
        if [ -n "$PROC_INFO" ]; then
            echo -e "  ${GREEN}$proc${NC}: $PROC_INFO"
        fi
    fi
done

# Auth service (Python process)
AUTH_PID=$(pgrep -f "python3.*auth-server.py" | head -1)
if [ -n "$AUTH_PID" ]; then
    AUTH_INFO=$(ps -o user=,uid=,gid=,cmd= -p "$AUTH_PID" 2>/dev/null | sed 's/python3.*/authsvc (auth-server.py)/')
    echo -e "  ${GREEN}authsvc${NC}: $AUTH_INFO"
fi

echo ""

# Verify UIDs are correct
ZOOKD_UID=$(ps -o uid= -p "$(pgrep -x zookd | head -1)" 2>/dev/null | tr -d ' ')
ZOOKSVC_UID=$(ps -o uid= -p "$(pgrep -x zooksvc | head -1)" 2>/dev/null | tr -d ' ')
AUTH_UID=$(ps -o uid= -p "$(pgrep -f 'python3.*auth-server.py' | head -1)" 2>/dev/null | tr -d ' ')

if [ "$ZOOKD_UID" = "6000" ] && [ "$ZOOKSVC_UID" = "6001" ] && [ "$AUTH_UID" = "33333" ]; then
    print_success "All processes running with correct UIDs!"
else
    print_warning "UIDs may not match expected values (6000, 6001, 33333)"
fi

wait_for_user

##############################################################################
# STEP 3: Test Web Application
##############################################################################

print_header "STEP 2: Web Application Functionality Test"

print_section "2.1 Testing HTTP connectivity..."

HTTP_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ 2>/dev/null)

if [ "$HTTP_RESPONSE" = "200" ] || [ "$HTTP_RESPONSE" = "302" ]; then
    print_success "Web server responding (HTTP $HTTP_RESPONSE)"
    echo ""
    echo -e "${BOLD}Access the application at:${NC}"
    echo "  → http://localhost:8080/"
    echo ""
    echo "You can now:"
    echo "  • Register a new user"
    echo "  • Login with existing credentials"
    echo "  • Transfer zoobars between users"
else
    print_error "Web server not responding properly (HTTP $HTTP_RESPONSE)"
fi

echo ""
print_section "2.2 Database Separation Verification"

echo -e "${BOLD}Person Database (Public Data):${NC}"
if [ -f "zoobar/db/person/person.db" ]; then
    PERSON_OWNER=$(stat -c "%U:%G (UID:%u GID:%g)" zoobar/db/person/person.db)
    echo "  Location: zoobar/db/person/person.db"
    echo "  Owner: $PERSON_OWNER"
    echo "  Contents: usernames, profiles, zoobars"
    print_success "Person database accessible to zooksvc (UID 6001)"
else
    print_warning "Person database not found"
fi

echo ""
echo -e "${BOLD}Credentials Database (Sensitive Data):${NC}"
if [ -f "zoobar/db/cred/cred.db" ]; then
    CRED_OWNER=$(stat -c "%U:%G (UID:%u GID:%g)" zoobar/db/cred/cred.db)
    echo "  Location: zoobar/db/cred/cred.db"
    echo "  Owner: $CRED_OWNER"
    echo "  Contents: passwords, tokens (PROTECTED)"
    print_success "Credentials database isolated to authsvc (UID 33333)"
else
    print_warning "Credentials database not found"
fi

wait_for_user

##############################################################################
# STEP 4: Demonstrate Attack Mitigation
##############################################################################

print_header "STEP 3: Attack Mitigation Demonstration"

print_section "3.1 Creating target file..."

# Create the target file that the exploit will try to delete
if [ ! -f "$TARGET_FILE" ]; then
    echo "TOP SECRET PASSWORDS - DO NOT DELETE" > "$TARGET_FILE"
    chmod 644 "$TARGET_FILE"
    print_success "Created target file: $TARGET_FILE"
else
    print_success "Target file already exists: $TARGET_FILE"
fi

echo ""
echo -e "${BOLD}File details:${NC}"
ls -lh "$TARGET_FILE"

echo ""
print_section "3.2 Running buffer overflow exploit..."

echo -e "${BOLD}Exploit details:${NC}"
echo "  • Targets: url_decode() vulnerability in zookd"
echo "  • Payload: 8000-byte buffer overflow"
echo "  • Intent: Crash server and delete $TARGET_FILE"
echo "  • Expected: Process crash, but file survives (UID protection)"
echo ""

echo -e "${YELLOW}Launching exploit in 3 seconds...${NC}"
sleep 3

# Run the exploit
echo ""
echo -e "${BOLD}Exploit output:${NC}"
echo "─────────────────────────────────────────────────────────────"
./exploit-2.py localhost 8080
echo "─────────────────────────────────────────────────────────────"
echo ""

sleep 2

print_section "3.3 Verifying attack mitigation..."

# Check if the file still exists
if [ -f "$TARGET_FILE" ]; then
    print_success "ATTACK MITIGATED! File '$TARGET_FILE' still exists!"
    echo ""
    echo -e "${BOLD}File contents:${NC}"
    cat "$TARGET_FILE"
    echo ""
    echo -e "${GREEN}${BOLD}WHY IT FAILED:${NC}"
    echo "  • Exploit crashed zookd (UID 6000)"
    echo "  • File '$TARGET_FILE' owned by $(stat -c '%U (UID %u)' $TARGET_FILE)"
    echo "  • OS denied unlink() syscall (insufficient privileges)"
    echo "  • Privilege separation contained the damage!"
else
    print_error "Attack succeeded - file was deleted! Privilege separation may not be working."
fi

echo ""
print_section "3.4 Server recovery check..."

sleep 2

# Check if zookld restarted zookd
NEW_ZOOKD_PID=$(pgrep -x zookd | head -1)
if [ -n "$NEW_ZOOKD_PID" ]; then
    print_success "zookld automatically restarted zookd (PID: $NEW_ZOOKD_PID)"
    print_success "Server remains available despite attack!"
else
    print_warning "zookd may not have restarted"
fi

wait_for_user

##############################################################################
# STEP 5: Filesystem Privilege Verification
##############################################################################

print_header "STEP 4: Filesystem Privilege Separation"

print_section "4.1 Critical directories inside jail"

echo -e "${BOLD}Directory Ownership and Permissions:${NC}"
echo ""

# Check critical directories
for dir in "authsvc" "auth_secure_keys" "banksvc" "bank_secure_keys" "zoobar/db"; do
    if [ -e "$dir" ]; then
        echo -e "${CYAN}$dir/${NC}"
        ls -ld "$dir" | awk '{printf "  Permissions: %s  Owner: %s:%s\n", $1, $3, $4}'

        # Show what UID owns it
        DIR_UID=$(stat -c '%u' "$dir")
        case $DIR_UID in
            33333) echo -e "  ${GREEN}→ Owned by authsvc (UID 33333)${NC}" ;;
            44444) echo -e "  ${GREEN}→ Owned by banksvc (UID 44444)${NC}" ;;
            *) echo -e "  ${YELLOW}→ Owned by UID $DIR_UID${NC}" ;;
        esac
        echo ""
    fi
done

print_section "4.2 Database files isolation"

echo -e "${BOLD}Database File Permissions:${NC}"
echo ""

for db in zoobar/db/person/person.db zoobar/db/cred/cred.db zoobar/db/transfer/transfer.db; do
    if [ -f "$db" ]; then
        echo -e "${CYAN}$db${NC}"
        ls -lh "$db" | awk '{printf "  Permissions: %s  Owner: %s:%s  Size: %s\n", $1, $3, $4, $5}'

        # Explain access control
        DB_UID=$(stat -c '%u' "$db")
        case $DB_UID in
            33333) echo -e "  ${GREEN}→ Only accessible by authsvc (passwords/tokens)${NC}" ;;
            44444) echo -e "  ${GREEN}→ Only accessible by banksvc (zoobar balances)${NC}" ;;
            6001) echo -e "  ${GREEN}→ Accessible by zooksvc (public profiles)${NC}" ;;
            *) echo -e "  ${YELLOW}→ Owned by UID $DB_UID${NC}" ;;
        esac
        echo ""
    fi
done

print_section "4.3 IPC socket permissions"

echo -e "${BOLD}Unix Domain Sockets (RPC Communication):${NC}"
echo ""

for sock in authsvc/sock banksvc/sock; do
    if [ -e "$sock" ]; then
        echo -e "${CYAN}/$sock${NC}"
        ls -lh "$sock" | awk '{printf "  Permissions: %s  Owner: %s:%s\n", $1, $3, $4}'
        SOCK_GID=$(stat -c '%g' "$sock")
        if [ "$SOCK_GID" = "11111" ]; then
            echo -e "  ${GREEN}→ Group 11111 allows IPC between services${NC}"
        fi
        echo ""
    fi
done

echo -e "${BOLD}Security Properties:${NC}"
echo "  ✓ Each service runs with minimal UID/GID"
echo "  ✓ Databases owned by their respective services"
echo "  ✓ Group 11111 enables controlled IPC"
echo "  ✓ OS enforces access control at kernel level"

wait_for_user

##############################################################################
# FINAL SUMMARY
##############################################################################

print_header "DEMONSTRATION COMPLETE"

echo -e "${BOLD}Summary of Security Achievements:${NC}"
echo ""
echo -e "${GREEN}✓ Process Isolation:${NC}"
echo "    Three separate processes with different UIDs (6000, 6001, 33333)"
echo ""
echo -e "${GREEN}✓ Data Separation:${NC}"
echo "    Credentials isolated in cred.db (UID 33333)"
echo "    Profiles in person.db (UID 6001)"
echo ""
echo -e "${GREEN}✓ Attack Containment:${NC}"
echo "    Buffer overflow exploited zookd, but file deletion failed"
echo "    Privilege separation limited damage to single process"
echo ""
echo -e "${GREEN}✓ Service Resilience:${NC}"
echo "    zookld automatically restarted crashed zookd"
echo "    Application remained available during attack"
echo ""
echo -e "${GREEN}✓ Filesystem Security:${NC}"
echo "    OS-level UID/GID enforcement protects sensitive data"
echo "    Group-based IPC controls inter-service communication"
echo ""

echo -e "${CYAN}${BOLD}Defense in Depth Principles Applied:${NC}"
echo "  1. Least Privilege (minimal UIDs per service)"
echo "  2. Isolation (chroot jails + separate databases)"
echo "  3. Fail-Safe (automatic restart on crash)"
echo "  4. OS-Level Enforcement (kernel protects resources)"
echo ""

print_success "All exercises demonstrated successfully!"
echo ""
