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
```
mbedtls-rsa-example/
└── lib/
    └── mbedtls/
```
After doing so, open the main CMakeLists.txt file and change the following line:
```
option(USE_FETCHCONTENT "Use FetchContent to download MbedTLS" TRUE)
```
Change it to:
```
option(USE_FETCHCONTENT "Use FetchContent to download MbedTLS" FALSE)
```
With this setting, CMake will use the version of Mbed TLS you placed inside the lib folder instead of downloading it automatically.

## Arduino Installation and Setup

This project can be compiled and uploaded to an ESP32 board using `arduino-cli`, compatible with Arduino IDE 1.8.19. The following steps guide you through setting up the environment on a Linux system.

### 1. Install `arduino-cli`
To compile and upload the project, install `arduino-cli`:

```bash
curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/install.sh | sh
```

Move the `arduino-cli` binary to a system path (e.g., `/usr/local/bin`):
```bash
sudo mv arduino-cli /usr/local/bin/
```

Verify the installation:
```bash
arduino-cli version
```

### 2. Install ESP32 Core
The project is designed for ESP32, which includes the `mbedtls` library by default. Install the ESP32 core:

```bash
arduino-cli core update-index
arduino-cli core install esp32:esp32
```

Verify the core installation:
```bash
arduino-cli core list
```

### 3. Install Required Tools
Ensure that the necessary tools for compiling are installed:
```bash
sudo apt-get install gcc-xtensa-lx106 avrdude
```

### 4. Compile the Project
Navigate to the project directory containing `arduino_example.ino`:
```bash
cd /path/to/mbedtls-rsa-example
```

Compile the project for ESP32:
```bash
arduino-cli compile --fqbn esp32:esp32:esp32 /path/to/mbedtls-rsa-example
```

If you are using a specific ESP32 board (e.g., NodeMCU), find the appropriate `fqbn`:
```bash
arduino-cli board listall
```
For example, for NodeMCU:
```bash
arduino-cli compile --fqbn esp32:esp32:nodemcu-32s /path/to/mbedtls-rsa-example
```

### 5. Upload to ESP32 (Optional)
To upload the compiled code to an ESP32 board:
1. Connect the ESP32 board to your system.
2. Find the serial port:
   ```bash
   arduino-cli board list
   ```
3. Upload the code (replace `/dev/ttyUSB0` with your port):
   ```bash
   arduino-cli upload --fqbn esp32:esp32:esp32 --port /dev/ttyUSB0 /path/to/mbedtls-rsa-example
   ```

### 6. Monitor Serial Output
To view the serial output (e.g., RSA signature), use a serial monitor like `minicom`:
```bash
minicom -D /dev/ttyUSB0 -b 115200
```
Or use `screen`:
```bash
screen /dev/ttyUSB0 115200
```

### Notes
- The `mbedtls` library is included in the ESP32 core, so no additional installation is required.
- Ensure the project folder contains `arduino_example.ino` with the correct code (as provided in the repository).
- If you encounter memory issues, consider using a smaller RSA key size (e.g., 1024-bit) to optimize performance.
- For compatibility with Arduino IDE 1.8.19, the above `arduino-cli` setup mirrors its behavior.

If you encounter any issues, check the verbose output for more details:
```bash
arduino-cli compile --fqbn esp32:esp32:esp32 --verbose /path/to/mbedtls-rsa-example
```