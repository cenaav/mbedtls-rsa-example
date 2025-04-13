# Specify the minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Define the project name
project(mbedtls-rsa-example)

# Add a boolean option to choose between FetchContent and manual MbedTLS
# Default is FALSE (use manual MbedTLS)
option(USE_FETCHCONTENT "Use FetchContent to download MbedTLS" TRUE)

if(USE_FETCHCONTENT)
    # Include FetchContent module for downloading MbedTLS
    include(FetchContent)

    # Declare MbedTLS with a specific version
    FetchContent_Declare(
        mbedtls
        GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
        GIT_TAG v3.6.3
        GIT_SHALLOW TRUE
    )

    # Download and make MbedTLS available
    FetchContent_MakeAvailable(mbedtls)

    # Define the MbedTLS include directory
    set(MBEDTLS_INCLUDE_DIR ${mbedtls_SOURCE_DIR}/include)

    # Define the MbedTLS libraries (include mbedcrypto explicitly)
    set(MBEDTLS_LIBRARY MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)
else()
    # Use manually downloaded MbedTLS in lib/mbedtls/
    add_subdirectory(lib/mbedtls)

    # Define the MbedTLS include directory
    set(MBEDTLS_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/lib/mbedtls/include)

    # Define the MbedTLS libraries (include mbedcrypto explicitly)
    set(MBEDTLS_LIBRARY mbedtls mbedcrypto mbedx509)
endif()

# Copy the ssl/ directory to the build directory
file(COPY ${CMAKE_SOURCE_DIR}/ssl DESTINATION ${CMAKE_BINARY_DIR})

# Create the executable 'myapp'
add_executable(myapp src/main.c)

# Link the executable against MbedTLS libraries
target_link_libraries(myapp PRIVATE ${MBEDTLS_LIBRARY})

# Include MbedTLS headers
target_include_directories(myapp PRIVATE ${MBEDTLS_INCLUDE_DIR})