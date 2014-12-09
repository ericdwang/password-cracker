#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>


/**
 * Get the hexidecimal representation of a hash stored in an unsigned char
 * array.
 */
void get_hash_hex(char* hex, unsigned char* hash) {
    int i;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex + (i * 2), "%02x", hash[i]);
    }
    hex[64] = 0;
}

/**
 * Compute the SHA-256 hash of a string for a number of iterations and write
 * it to a buffer.
 */
void sha256(char* string, unsigned char* buffer, int iterations) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(buffer, &sha256);
    int i;
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (i = 1; i < iterations; i++) {
        get_hash_hex(hex, buffer);
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, hex, SHA256_DIGEST_LENGTH * 2);
        SHA256_Final(buffer, &sha256);
    }
}
