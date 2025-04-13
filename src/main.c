#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>

// JSON data to process
static const char *json_data = "{\"en\":0,\"fb\":\"F1\",\"fa\":1,\"fl\":1,\"fv\":1,\"temp_home\":22.2,\"temp_refrigerator\":23.3,\"humidity\":24.4,\"fault_power\":\"k\",\"hw\":\"G\"}";

// Read a file into a buffer
static char *read_file(const char *filename, size_t *out_len) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        printf("Failed to open %s\n", filename);
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buffer = malloc(len + 1);
    if (!buffer) {
        printf("Memory allocation failed\n");
        fclose(fp);
        return NULL;
    }
    size_t read_len = fread(buffer, 1, len, fp);
    if (read_len != (size_t)len) {
        printf("Failed to read %s\n", filename);
        free(buffer);
        fclose(fp);
        return NULL;
    }
    buffer[len] = '\0';
    *out_len = len + 1;
    fclose(fp);
    return buffer;
}

// Base64 encode data
static char *base64_encode_data(const unsigned char *input, size_t input_len) {
    size_t output_len = 0;
    unsigned char output[512];
    int ret = mbedtls_base64_encode(output, sizeof(output), &output_len, input, input_len);
    if (ret != 0) {
        printf("Base64 encode failed: -0x%04x\n", -ret);
        return NULL;
    }
    char *result = malloc(output_len + 1);
    if (!result) {
        printf("Base64 encode: Memory allocation failed\n");
        return NULL;
    }
    memcpy(result, output, output_len);
    result[output_len] = '\0';
    return result;
}

// Base64 decode data (for verification)
static unsigned char *base64_decode_data(const char *input, size_t *output_len) {
    unsigned char output[512];
    int ret = mbedtls_base64_decode(output, sizeof(output), output_len,
                                   (const unsigned char *)input, strlen(input));
    if (ret != 0) {
        printf("Base64 decode failed: -0x%04x\n", -ret);
        return NULL;
    }
    unsigned char *result = malloc(*output_len);
    if (!result) {
        printf("Base64 decode: Memory allocation failed\n");
        return NULL;
    }
    memcpy(result, output, *output_len);
    return result;
}

// Calculate SHA-256 hash, convert to hex, and sign the hex string
static char *sign_message(mbedtls_pk_context *priv_key, const char *message,
                          mbedtls_ctr_drbg_context *ctr_drbg) {
    // Calculate SHA-256 hash
    unsigned char hash[32];
    int ret = mbedtls_sha256((const unsigned char *)message, strlen(message), hash, 0);
    if (ret != 0) {
        printf("Hashing failed: -0x%04x\n", -ret);
        return NULL;
    }

    // Convert hash to hex (64 chars)
    char hex_hash[65]; // 64 chars + null terminator
    for (size_t i = 0; i < 32; i++) {
        sprintf(hex_hash + (i * 2), "%02x", hash[i]);
    }
    hex_hash[64] = '\0';
    printf("SHA-256 Hash (hex): %s\n", hex_hash);

    // Hash the hex string
    unsigned char hex_hash_digest[32];
    ret = mbedtls_sha256((const unsigned char *)hex_hash, strlen(hex_hash), hex_hash_digest, 0);
    if (ret != 0) {
        printf("Hashing hex string failed: -0x%04x\n", -ret);
        return NULL;
    }

    // Sign the hex string's hash
    unsigned char signature[MBEDTLS_MPI_MAX_SIZE];
    size_t sig_len = 0;
    ret = mbedtls_pk_sign(priv_key, MBEDTLS_MD_SHA256, hex_hash_digest, sizeof(hex_hash_digest),
                          signature, sizeof(signature), &sig_len,
                          mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) {
        printf("Signing failed: -0x%04x\n", -ret);
        return NULL;
    }

    return base64_encode_data(signature, sig_len);
}

// Verify the signature of the hex hash
static int verify_message(mbedtls_pk_context *pub_key, const char *message) {
    // Recalculate SHA-256 hash
    unsigned char hash[32];
    int ret = mbedtls_sha256((const unsigned char *)message, strlen(message), hash, 0);
    if (ret != 0) {
        printf("Hashing failed: -0x%04x\n", -ret);
        return 0;
    }

    // Convert hash to hex
    char hex_hash[65];
    for (size_t i = 0; i < 32; i++) {
        sprintf(hex_hash + (i * 2), "%02x", hash[i]);
    }
    hex_hash[64] = '\0';

    // Hash the hex string
    unsigned char hex_hash_digest[32];
    ret = mbedtls_sha256((const unsigned char *)hex_hash, strlen(hex_hash), hex_hash_digest, 0);
    if (ret != 0) {
        printf("Hashing hex string failed: -0x%04x\n", -ret);
        return 0;
    }

    // Verification is done in main with stored signature
    return 1; // Return 1 to indicate hash preparation succeeded
}

int main(void) {
    printf("Starting Device RSA Demo\n");

    // Initialize contexts
    mbedtls_pk_context pk_priv, pk_pub;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    char *priv_pem = NULL, *pub_pem = NULL;
    size_t priv_len = 0, pub_len = 0;
    const char *pers = "rsa_device";
    int ret = 1;
    char *signature = NULL;

    mbedtls_pk_init(&pk_priv);
    mbedtls_pk_init(&pk_pub);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Seed RNG
    printf("Seeding random number generator...\n");
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        printf("Failed to seed RNG: -0x%04x\n", -ret);
        goto exit;
    }
    printf("RNG seeded\n");

    // Load device private key
    printf("Loading private key (ssl/private_key.pem)...\n");
    priv_pem = read_file("ssl/private_key.pem", &priv_len);
    if (!priv_pem) goto exit;
    ret = mbedtls_pk_parse_key(&pk_priv, (const unsigned char *)priv_pem,
                               priv_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        printf("Failed to parse private key: -0x%04x\n", -ret);
        goto exit;
    }
    printf("Private key loaded\n");

    // Load device public key (for verification)
    printf("Loading public key (ssl/public_key.pem)...\n");
    pub_pem = read_file("ssl/public_key.pem", &pub_len);
    if (!pub_pem) goto exit;
    ret = mbedtls_pk_parse_public_key(&pk_pub, (const unsigned char *)pub_pem, pub_len);
    if (ret != 0) {
        printf("Failed to parse public key: -0x%04x\n", -ret);
        goto exit;
    }
    printf("Public key loaded\n");

    // Step 1: Prepare JSON
    printf("\n=== Preparing JSON ===\n");
    printf("JSON: %s\n", json_data);

    // Step 2: Calculate SHA-256, convert to hex, and sign
    printf("\n=== Hashing and Signing Hex Hash ===\n");
    signature = sign_message(&pk_priv, json_data, &ctr_drbg);
    if (!signature) goto exit;
    printf("Base64 RSA Signature: %s\n", signature);

    // Step 3: Verify signature
    printf("\n=== Verifying Signature ===\n");
    // Prepare hex hash for verification
    unsigned char hash[32];
    ret = mbedtls_sha256((const unsigned char *)json_data, strlen(json_data), hash, 0);
    if (ret != 0) {
        printf("Hashing failed: -0x%04x\n", -ret);
        goto exit;
    }
    char hex_hash[65];
    for (size_t i = 0; i < 32; i++) {
        sprintf(hex_hash + (i * 2), "%02x", hash[i]);
    }
    hex_hash[64] = '\0';

    // Hash the hex string
    unsigned char hex_hash_digest[32];
    ret = mbedtls_sha256((const unsigned char *)hex_hash, strlen(hex_hash), hex_hash_digest, 0);
    if (ret != 0) {
        printf("Hashing hex string failed: -0x%04x\n", -ret);
        goto exit;
    }

    // Verify signature
    size_t sig_len = 0;
    unsigned char *sig_bytes = base64_decode_data(signature, &sig_len);
    if (!sig_bytes) goto exit;
    ret = mbedtls_pk_verify(&pk_pub, MBEDTLS_MD_SHA256, hex_hash_digest, sizeof(hex_hash_digest),
                            sig_bytes, sig_len);
    free(sig_bytes);
    printf("RSA Signature Verification: %s\n", ret == 0 ? "successful" : "failed");
    if (ret != 0) {
        printf("Verification failed: -0x%04x\n", -ret);
        goto exit;
    }

    // Step 4: Send to server (simulated)
    printf("\n=== Sending to Server ===\n");
    printf("Sending json: %s\n", json_data);
    printf("Sending signature: %s\n", signature);

    ret = 0; // Success

exit:
    printf("\nCleaning up...\n");
    free(priv_pem);
    free(pub_pem);
    free(signature);
    mbedtls_pk_free(&pk_priv);
    mbedtls_pk_free(&pk_pub);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    printf("Done\n");
    return ret;
}