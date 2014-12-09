#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>

#include "sha256_functions.h"


int main(int argc, char **argv) {
    int iterations = 1;
    int string_arg = 0;
    char* string;

    // Parse arguments
    int c;
    while((c = getopt(argc, argv, "h:m:n:l:u:d:p:i:")) != -1) {
        switch(c) {
            case 'h':
                string = (char*) malloc(strlen(optarg) + 1);
                strcpy(string, optarg);
                string_arg = 1;
                break;
            case 'i':
                iterations = atoi(optarg);
                break;
        }
    }

    // Check arguments
    if (!string_arg) {
        printf("Usage: ./sha256 -h <string> -i <iterations (default 1)>\n");
        return 1;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];

    printf("Hashing \"%s\" %d number of times\n", string, iterations);
    // Hash the string for the desired number of times and print the output
    sha256(string, hash, iterations);
    get_hash_hex(hex, hash);
    printf("%s\n", hex);
    return 0;
}
