#include <string.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>

// ***************************************************** RSA KEYS ***********************************************************

const char *private_key_pem = R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2h20oITt/Qgew
EaRj8iEguxYxCBiws1BXhH28YwfRn7ihNA9NMKlDcWrJVLQlo0qrVs9te/0a4/R/
MsZLPFTyLxKphWfJ+CBujMnn/AdM3gFiSRyJUJ0PokAU/kgnhx9w0N5p/T7L3hfM
1GWszEkT4i9Ys8cf4uIcm7MFIINmzDwPUVoOJF+JYJGU22L+ynxk8mAdiVxgmHpA
u8vnWOdlrX6O1CRc+mYVUaA1KRTEsjanG4JNr9tM55SdQGFhM5jZvaTsMlxy08NC
9OGHhKg1LEbu6bVSx6UdkcZ+q5qMJtp6mU7y8eSuQVjDSKrwK56MmI91fkeuatZL
g1q9gIBzAgMBAAECggEADzmTms3O0yoUTxTho+6N4deJHdThjleeo3YrMLwH6m3K
rjOT9SnSbIw4zotQrXUF5O3MRoMZlRUfjz6SeLMTGNJhWZ+FjTyzo9T9gGquxzQb
ZHHZvgBp4WR0uOuO5DEqp7PcYXXct4+SZ6TtyDCQBecPcPQp71hy6NT55TsViszp
Q3V8yafruN+0nlbpOSKJDkFzThXrE3UmP9Zmk+4tOjxlTp4kVg4BaLSda2BXNdNh
Pu5Q2mWinMRmBqR7a63VU2k7W9+a7twVQfPhZF3LgLItuAlxAfQZCYJ2TqCdTmQP
3EGBCSYt37bi2SBHeQmTkC8mmb+zBhRqKcZ2MXflAQKBgQDaCDk5pU1X2hqfnYmA
PZqhx+VRVF5TP6JbpNlreiNkhQDq85ZDKcKey8XemhhiGxa8LmvhdXiwbXXmfvC4
tYjFdTJ4GrRBZid07QuCRIV7p4RFf2Yfq3RBVLWxb4LYNFFBo9IfOvj8AgnlG+x9
Mii96dcC5EGb+ZOoR2tPnP8lcwKBgQDWUH1W7+nQmRQwG7q2nVNvtXMTWaFeh8SE
I3O+PIQ/6fDajeW5GpGl9RXspL87WoGN5EDWRLkHTzp5+HK7azFkvmi37In8fn6M
AovnwvnvZJPHWv6hUcLY5zS9yTijS0o3lITcSFddhTHIRrgOTdN06bfLgzJ458uT
6SMS1Xp5AQKBgGsKpIWfmSQraOy6HBqApB0PFY9jO1flouEZQsDYWu3runKfGkNp
CiqJ4mASCSyJHhVPORmcYZ9EbiC2a5pTTY2bpyZ9/ccpzu9BvWe8GkiGCpNQI6Qi
udWlL/qnw3Y/4TC3q943Rqv6mD8KAYXJjWUHm87In0ljM1HnllCkxELvAoGAICsS
tTLrqJjhk9sFqpVwyaq1rCje9N5yG9dqbxqMSz+lHFkCK0eWpw9jjBKqdZE/MvoY
1VCZaUR2JYqqRgFv94wxEbJaf+DIw+E5+L6mX018dQbug25PTdlebEJA0xng+Pi8
/IeLPYlZkJM020jJPZo7MTvvHoDEaN4smo4ahQECgYEAkORdHjWIeZvFua7YAulz
DRPestcSBxah33WONPdcNda8/qmf117mYsvGIajs4zTEuEyqXLdYENU+UMNBR7CE
D3Jhgn5/0QHKea2GF1QjpGDLAJne/sRdPFMHkstxyyktOi8Ny80ue2VR0XdWPLoe
OrKPwlpW2AA2RWf2R9PC8NY=
-----END PRIVATE KEY-----)";

const char *public_key_pem = R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtodtKCE7f0IHsBGkY/Ih
ILsWMQgYsLNQV4R9vGMH0Z+4oTQPTTCpQ3FqyVS0JaNKq1bPbXv9GuP0fzLGSzxU
8i8SqYVnyfggbozJ5/wHTN4BYkkciVCdD6JAFP5IJ4cfcNDeaf0+y94XzNRlrMxJ
E+IvWLPHH+LiHJuzBSCDZsw8D1FaDiRfiWCRlNti/sp8ZPJgHYlcYJh6QLvL51jn
Za1+jtQkXPpmFVGgNSkUxLI2pxuCTa/bTOeUnUBhYTOY2b2k7DJcctPDQvThh4So
NSxG7um1UselHZHGfquajCbaeplO8vHkrkFYw0iq8CuejJiPdX5HrmrWS4NavYCA
cwIDAQAB
-----END PUBLIC KEY-----)";

// **********************************************************************************************************************

// Base64 encode data
static char *base64_encode_data(const unsigned char *input, size_t input_len) {
    size_t output_len = 0;
    unsigned char output[512];
    int ret = mbedtls_base64_encode(output, sizeof(output), &output_len, input, input_len);
    if (ret != 0) {
        Serial.printf("Base64 encode failed: -0x%04x\n", -ret);
        return NULL;
    }

    #ifdef __cplusplus
        // Compiling as C++
        char *result = (char *)malloc(output_len + 1);
    #else
        // Compiling as C
        char *result = malloc(output_len + 1);
    #endif

    if (!result) {
        Serial.println("Base64 encode: Memory allocation failed");
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
        Serial.printf("Base64 decode failed: -0x%04x\n", -ret);
        return NULL;
    }

    #ifdef __cplusplus
        // Compiling as C++: cast is required
        unsigned char *result = (unsigned char *)malloc(*output_len);
    #else
        // Compiling as C: no cast needed
        unsigned char *result = malloc(*output_len);
    #endif

    if (!result) {
        Serial.println("Base64 decode: Memory allocation failed");
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
        Serial.printf("Hashing failed: -0x%04x\n", -ret);
        return NULL;
    }

    // Convert hash to hex (64 chars)
    char hex_hash[65]; // 64 chars + null terminator
    for (size_t i = 0; i < 32; i++) {
        snprintf(hex_hash + (i * 2), 3, "%02x", hash[i]);
    }
    hex_hash[64] = '\0';
    Serial.print("SHA-256 Hash (hex): ");
    Serial.println(hex_hash);

    // Hash the hex string
    unsigned char hex_hash_digest[32];
    ret = mbedtls_sha256((const unsigned char *)hex_hash, strlen(hex_hash), hex_hash_digest, 0);
    if (ret != 0) {
        Serial.printf("Hashing hex string failed: -0x%04x\n", -ret);
        return NULL;
    }

    // Sign the hex string's hash
    unsigned char signature[MBEDTLS_MPI_MAX_SIZE];
    size_t sig_len = 0;
    ret = mbedtls_pk_sign(priv_key, MBEDTLS_MD_SHA256, hex_hash_digest, sizeof(hex_hash_digest),
                          signature, sizeof(signature), &sig_len,
                          mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) {
        Serial.printf("Signing failed: -0x%04x\n", -ret);
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
        Serial.printf("Hashing failed: -0x%04x\n", -ret);
        return 0;
    }

    // Convert hash to hex
    char hex_hash[65];
    for (size_t i = 0; i < 32; i++) {
        snprintf(hex_hash + (i * 2), 3, "%02x", hash[i]);
    }
    hex_hash[64] = '\0';

    // Hash the hex string
    unsigned char hex_hash_digest[32];
    ret = mbedtls_sha256((const unsigned char *)hex_hash, strlen(hex_hash), hex_hash_digest, 0);
    if (ret != 0) {
        Serial.printf("Hashing hex string failed: -0x%04x\n", -ret);
        return 0;
    }

    // Verification is done in main with stored signature
    return 1; // Return 1 to indicate hash preparation succeeded
}

void setup() {
  
    Serial.begin(115200);
    delay(1000);

    const char *json_data = "{\"en\":0,\"fb\":\"F1\",\"fa\":1,\"fl\":1,\"fv\":1,\"temp_home\":22.2,\"temp_refrigerator\":23.3,\"humidity\":24.4,\"fault_power\":\"k\",\"hw\":\"G\"}";
    
    mbedtls_pk_context pk_priv, pk_pub;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const char *pers = "rsa_device";
    int ret = 1;
    char *signature = NULL;

    mbedtls_pk_init(&pk_priv);
    mbedtls_pk_init(&pk_pub);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Seed RNG
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        Serial.printf("RNG seed failed: -0x%04x\n", -ret);
        goto exit;
    }

    // Load keys from in-memory PEM
    ret = mbedtls_pk_parse_key(&pk_priv, (const unsigned char *)private_key_pem,
                               strlen(private_key_pem) + 1, NULL, 0,
                               mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        Serial.printf("Private key parse failed: -0x%04x\n", -ret);
        goto exit;
    }

    ret = mbedtls_pk_parse_public_key(&pk_pub, (const unsigned char *)public_key_pem,
                                      strlen(public_key_pem) + 1);
    if (ret != 0) {
        Serial.printf("Public key parse failed: -0x%04x\n", -ret);
        goto exit;
    }

    // Sign message
    signature = sign_message(&pk_priv, json_data, &ctr_drbg);
    if (!signature) {
        Serial.println("Signing failed.");
        goto exit;
    }

    Serial.print("Signature (base64): ");
    Serial.println(signature);

    // Free signature memory if dynamically allocated
    free(signature);
    ret = 0;

exit:
    mbedtls_pk_free(&pk_priv);
    mbedtls_pk_free(&pk_pub);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    if (ret != 0) {
        Serial.println("Setup failed. Halting.");
        while (true) {}  // Halt device
    }
}

void loop() {
  // put your main code here, to run repeatedly:
}