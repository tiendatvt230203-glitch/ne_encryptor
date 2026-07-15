#!/bin/bash
REMOTE="/home/clover/NE_TEST_MAC_FW"
KEY="/root/.ssh/id_ed25519"

DEPLOY_LIST="bin"

for IP in "10.5.15.54" "10.5.15.55"
do
    echo "Deploying to $IP..."
    for ITEM in $DEPLOY_LIST
    do
        scp -i "$KEY" -o StrictHostKeyChecking=no -r "$ITEM" root@$IP:$REMOTE/
    done
done
echo "Done!"
