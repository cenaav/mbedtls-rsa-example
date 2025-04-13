#!/bin/bash

# Script to run the mbedtls-rsa-example demo

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXECUTABLE="$SCRIPT_DIR/build/myapp"

# Check if the executable exists
if [ ! -f "$EXECUTABLE" ]; then
    echo "Error: 'myapp' executable not found in build/. Please run 'build.sh' first."
    exit 1
fi

# Run the program
echo "Running mbedtls-rsa-example demo..."
"$EXECUTABLE"