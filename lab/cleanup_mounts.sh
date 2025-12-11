#!/bin/bash

# Unmount directories mounted by setup.sh
# We use lazy unmount (-l) to detach them even if they are busy, 
# and force (-f) if necessary, though -l is usually safer for system stability.

echo "Unmounting bind mounts in lab directory..."

MOUNT_POINTS=(
    "usr"
    "lib"
    "lib64"
    "bin"
    "etc"
    "run"
    "zoobar/sqlalchemy"
    "zoobar/flask"
    "zoobar/werkzeug"
    "zoobar/itsdangerous"
    "zoobar/web3"
    "zoobar/dateutil"
    "zoobar/dotenv"
    "zoobar/eth_account"
    "zoobar/solcx"
)

# Unmount in reverse order might be safer for nested mounts, but these look mostly flat.
for dir in "${MOUNT_POINTS[@]}"; do
    # Check if mounted first to avoid errors
    if mountpoint -q "$dir"; then
        echo "Unmounting $dir..."
        sudo umount -l "$dir"
    else
        echo "$dir is not mounted."
    fi
done

echo "Cleanup complete. You can now run setup.sh."
