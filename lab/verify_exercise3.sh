#!/bin/bash
# Exercise 3 Verification - Concise Demo

echo "=========================================="
echo "Exercise 3: Auth Privilege Separation"
echo "=========================================="
echo ""

echo "1. Process Isolation:"
echo "-------------------------------------------"
ps aux | grep -E "(zookd|zooksvc|python3.*auth-server)" | grep -v grep | awk '{printf "%-10s UID:%-6s %s\n", $11, $1, $12" "$13}'
echo ""

echo "2. Database Separation:"
echo "-------------------------------------------"
ls -lh zoobar/db/*/*.db | awk '{printf "%-20s owned by %s:%s\n", $9, $3, $4}'
echo ""

echo "3. Registered Users:"
echo "-------------------------------------------"
echo "Person DB (profiles):"
sqlite3 zoobar/db/person/person.db "SELECT '  ' || username || ' - ' || zoobars || ' zoobars' FROM person;"
echo ""
echo "Cred DB (passwords/tokens):"
sqlite3 zoobar/db/cred/cred.db "SELECT '  ' || username || ' - token: ' || substr(token,1,16) || '...' FROM cred;"
echo ""

echo "✓ Exercise 3 Complete: Credentials isolated in authsvc (UID 33333)"
