
# mbedtls-rsa-signing-demo

A C project demonstrating RSA signing and verification of a JSON message using Mbed TLS.

## Features

-   Computes SHA-256 hash of a JSON string and converts it to a hex string.
-   Signs the hex hash with an RSA private key.
-   Verifies the signature with an RSA public key.
-   Built with Mbed TLS for secure RSA cryptography.
-   Includes scripts to generate keys and run the demo.
-   Ideal for learning RSA signing or securing IoT device messages.

## Prerequisites

-   C compiler (e.g., GCC)
-   make (for building with Makefile)
-   openssl (for key generation)
-   Mbed TLS (installed manually or via FetchContent)
-   Bash (for running scripts)

## Installation
Clone this repository:
```
git clone https://github.com/cenaav/mbedtls-rsa-example.git
cd mbedtls-rsa-example
```

## Mbed TLS Library
This project uses Mbed TLS, version 3.6.3.

You can provide your own copy of the Mbed TLS source manually by downloading it and placing it inside the lib directory of this project:
mbedtls-rsa-example/
└── lib/
    └── mbedtls/
After doing so, open the main CMakeLists.txt file and change the following line:
```
option(USE_FETCHCONTENT "Use FetchContent to download MbedTLS" TRUE)
```
Change it to:
```
option(USE_FETCHCONTENT "Use FetchContent to download MbedTLS" FALSE)
```
With this setting, CMake will use the version of Mbed TLS you placed inside the lib folder instead of downloading it automatically.