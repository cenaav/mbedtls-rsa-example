#!/bin/bash

# Script to generate RSA keys for mbedtls-rsa-example

# Check for openssl
if ! command -v openssl >/dev/null 2>&1; then
    echo "Error: 'openssl' is not installed. Please install it (e.g., 'sudo apt install openssl')."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSL_DIR="$SCRIPT_DIR/ssl"

# Create ssl directory
echo "Creating ssl/ directory..."
mkdir -p "$SSL_DIR"

# Generate 2048-bit RSA private key
echo "Generating private key (ssl/private_key.pem)..."
openssl genrsa -out "$SSL_DIR/private_key.pem" 2048
if [ $? -ne 0 ]; then
    echo "Error: Failed to generate private key."
    exit 1
fi

# Generate public key
echo "Generating public key (ssl/public_key.pem)..."
openssl rsa -in "$SSL_DIR/private_key.pem" -pubout -out "$SSL_DIR/public_key.pem"
if [ $? -ne 0 ]; then
    echo "Error: Failed to generate public key."
    exit 1
fi

echo "RSA keys generated successfully in ssl/."