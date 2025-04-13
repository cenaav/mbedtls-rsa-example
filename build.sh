#!/bin/bash

# Script to build and run the mbedtls-rsa-example project

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"

# Check for cmake
if ! command -v cmake >/dev/null 2>&1; then
    echo "Error: 'cmake' is not installed. Please install it (e.g., 'sudo apt install cmake')."
    exit 1
fi

# Check for make
if ! command -v make >/dev/null 2>&1; then
    echo "Error: 'make' is not installed. Please install it (e.g., 'sudo apt install make')."
    exit 1
fi

# Create build directory
mkdir -p "$BUILD_DIR"
echo "Created build directory: $BUILD_DIR"

# Change to build directory
cd "$BUILD_DIR" || { echo "Failed to change to build directory"; exit 1; }

# Run cmake
echo "Running cmake..."
cmake ..
if [ $? -ne 0 ]; then
    echo "CMake failed"
    exit 1
fi

# Run make
echo "Running make..."
make
if [ $? -ne 0 ]; then
    echo "Make failed"
    exit 1
fi

# Check for executable
if [ -f "./myapp" ]; then
    echo "Build successful: myapp created"
else
    echo "Build failed: myapp not found"
    exit 1
fi

# Run the program
echo "Running mbedtls-rsa-example demo..."
./myapp