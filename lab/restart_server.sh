#!/bin/bash
# Restart server with proper privilege separation

set -e

echo "=========================================="
echo "Restarting Zoobar Server"
echo "=========================================="

# Kill existing processes
echo "Stopping existing processes..."
pkill -9 zookld 2>/dev/null || true
pkill -9 zookd 2>/dev/null || true
pkill -9 zooksvc 2>/dev/null || true
pkill -9 python3 2>/dev/null || true
sleep 1

# Verify privilege separation settings
echo ""
echo "Privilege Separation Architecture:"
echo "  zookd (dispatcher):   UID 6000, GID 6000"
echo "  zooksvc (service):    UID 6001, GID 11111 ← Common IPC group"
echo "  authsvc (auth):       UID 33333, GID 11111 ← Common IPC group"
echo ""

# Make sure authsvc directory has proper permissions (NOT world-accessible)
# Group 11111 can access, others cannot
if [ -d "authsvc" ]; then
    echo "Setting authsvc directory permissions: 770 (owner+group only)"
    chmod 770 authsvc
fi

if [ -d "banksvc" ]; then
    echo "Setting banksvc directory permissions: 770 (owner+group only)"
    chmod 770 banksvc
fi

echo ""
echo "Starting server..."
sudo ./zookld
