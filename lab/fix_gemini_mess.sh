#!/bin/bash

set -e  # Exit on error

echo "=========================================="
echo "Fixing Gemini's Mess - Phase 1"
echo "Cleaning up WRONG location directories..."
echo "=========================================="

WRONG_LOC="/home/amirkhalifa/Desktop/Advanced_cyber/lab"
CORRECT_LOC="/home/amirkhalifa/Desktop/Advanced_cyber/lab/lab"

# Clean up wrong location
echo "Removing root-owned directories from $WRONG_LOC..."
rm -rf "$WRONG_LOC"/authsvc \
       "$WRONG_LOC"/banksvc \
       "$WRONG_LOC"/auth_secure_keys \
       "$WRONG_LOC"/bank_secure_keys \
       "$WRONG_LOC"/bin \
       "$WRONG_LOC"/etc \
       "$WRONG_LOC"/lib \
       "$WRONG_LOC"/lib64 \
       "$WRONG_LOC"/run \
       "$WRONG_LOC"/usr \
       "$WRONG_LOC"/zoobar

echo "✅ Phase 1 complete!"
echo ""
echo "=========================================="
echo "Phase 2: Fixing permissions in CORRECT location"
echo "=========================================="

# Fix the critical zoobar/db directory ownership
echo "Fixing zoobar/db directory ownership..."
chown -R amirkhalifa:11111 "$CORRECT_LOC"/zoobar/db
chmod 770 "$CORRECT_LOC"/zoobar/db

# Also fix any database files that might exist
if [ -f "$CORRECT_LOC/zoobar/db/person/person.db" ]; then
    echo "Fixing person.db ownership..."
    chown amirkhalifa:11111 "$CORRECT_LOC"/zoobar/db/person/person.db
    chmod 660 "$CORRECT_LOC"/zoobar/db/person/person.db
fi

if [ -f "$CORRECT_LOC/zoobar/db/cred/cred.db" ]; then
    echo "Fixing cred.db ownership..."
    chown 33333:11111 "$CORRECT_LOC"/zoobar/db/cred/cred.db
    chmod 660 "$CORRECT_LOC"/zoobar/db/cred/cred.db
fi

if [ -f "$CORRECT_LOC/zoobar/db/transfer/transfer.db" ]; then
    echo "Fixing transfer.db ownership..."
    chown amirkhalifa:11111 "$CORRECT_LOC"/zoobar/db/transfer/transfer.db
    chmod 660 "$CORRECT_LOC"/zoobar/db/transfer/transfer.db
fi

# Remove old service directories to recreate fresh
echo "Removing old service directories in correct location..."
rm -rf "$CORRECT_LOC"/authsvc \
       "$CORRECT_LOC"/banksvc \
       "$CORRECT_LOC"/auth_secure_keys \
       "$CORRECT_LOC"/bank_secure_keys \
       "$CORRECT_LOC"/bin \
       "$CORRECT_LOC"/etc \
       "$CORRECT_LOC"/lib \
       "$CORRECT_LOC"/lib64 \
       "$CORRECT_LOC"/run \
       "$CORRECT_LOC"/usr

echo "✅ Phase 2 complete!"
echo ""
echo "=========================================="
echo "Phase 3: Running setup.sh from CORRECT location"
echo "=========================================="

cd "$CORRECT_LOC"
# Preserve the original user for the chown commands in setup.sh
export ORIGINAL_USER=amirkhalifa
sudo -E -u root bash -c "USER=amirkhalifa ./setup.sh"

echo "✅ Phase 3 complete!"
echo ""
echo "=========================================="
echo "🎉 Fix Complete! Now you can:"
echo "1. cd $CORRECT_LOC"
echo "2. make clean && make"
echo "3. sudo ./zookld"
echo "4. Test registration at http://localhost:8080"
echo "=========================================="
