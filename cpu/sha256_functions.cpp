#include <openssl/sha.h>

static const int LOWERCASE_START = 97;
static const int DIGIT_START = 48;

/**
 * Convert a decimal number to hexidecimal.
 */
int to_hex(int number) {
    if (number < 10) {
        return number + DIGIT_START;
    } else {
        return number + LOWERCASE_START - 10;
    }
}

/**
 * Get the hexidecimal representation of a hash stored in an unsigned char
 * array.
 */
void get_hash_hex(char* hex, unsigned char* hash) {
    int i;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        int value = hash[i];
        hex[i * 2 + 1] = to_hex(value % 16);
        hex[i * 2] = to_hex(value / 16);
    }
    hex[64] = 0;
}

/**
 * Compute the SHA-256 hash of a string for a number of iterations and write
 * it to a buffer.
 */
void sha256(char* string, int length, unsigned char* buffer, int iterations) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, length);
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
