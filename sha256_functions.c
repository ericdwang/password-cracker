#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>


/**
 * Compute the SHA-256 hash of a string and write it to a buffer.
 */
void sha256(char* string, unsigned char* buffer) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(buffer, &sha256);
}

/**
 * Print the hexidecimal representation of a hash stored in an unsigned char
 * array.
 */
void print_hash(unsigned char* hash) {
    char output[SHA256_DIGEST_LENGTH * 2 + 1];
    int i;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = 0;
    printf("%s\n", output);
}
