#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#include "sha256_functions.h"


int main (int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: ./sha256 <string>\n");
        return 1;
    }

    // Print the hash of the input
    unsigned char buffer[SHA256_DIGEST_LENGTH];
    sha256(argv[1], buffer);
    print_hash(buffer);
    return 0;
}
