#!/bin/sh

echo "Launching periodic checker..."
/bin/periodic-checks.sh &
echo "Done"
echo "Launching nginx..."
nginx -g "daemon off;"
