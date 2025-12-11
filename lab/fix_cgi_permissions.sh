#!/bin/bash
# Quick fix for index.cgi and server script permissions

set -e

echo "Killing any running zook processes..."
pkill -9 zookld 2>/dev/null || true
pkill -9 zookd 2>/dev/null || true
pkill -9 zooksvc 2>/dev/null || true
pkill -9 python3 2>/dev/null || true
sleep 1

echo "Fixing index.cgi permissions..."
chmod 775 /home/amirkhalifa/Desktop/Advanced_cyber/lab/lab/zoobar/index.cgi

echo "Fixing Python server scripts permissions..."
chmod 755 /home/amirkhalifa/Desktop/Advanced_cyber/lab/lab/zoobar/auth-server.py
chmod 755 /home/amirkhalifa/Desktop/Advanced_cyber/lab/lab/zoobar/bank-server.py
chmod 755 /home/amirkhalifa/Desktop/Advanced_cyber/lab/lab/zoobar/profile-server.py 2>/dev/null || true

echo "Fixing zoobar directory permissions..."
chmod 755 /home/amirkhalifa/Desktop/Advanced_cyber/lab/lab/zoobar

echo "Making zoobar/db world-accessible temporarily..."
chmod 777 /home/amirkhalifa/Desktop/Advanced_cyber/lab/lab/zoobar/db

# Fix database subdirectories if they exist
for dbdir in /home/amirkhalifa/Desktop/Advanced_cyber/lab/lab/zoobar/db/*; do
    if [ -d "$dbdir" ]; then
        echo "Fixing $dbdir permissions..."
        chmod 777 "$dbdir"
        # Fix any .db files inside
        for dbfile in "$dbdir"/*.db; do
            if [ -f "$dbfile" ]; then
                chmod 666 "$dbfile"
            fi
        done
    fi
done

echo "✅ Permissions fixed!"
echo ""
echo "Now you can run: sudo ./zookld"
