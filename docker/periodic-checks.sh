#!/bin/sh

export SLEEP=86400

echo "Periodic Checker launched!"
while :; do
    echo "Checking for all websites on $(date)...";
    ./check_https.py;
    echo "Done checking on $(date).";
    echo "Sleeping for $SLEEP seconds...";
    sleep $SLEEP;
    echo "Done!"
done
