#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/sha.h>

#include "sha256_functions.h"


// The ASCII printable characters are 32 to 126 (inclusive)
const int LOWERCASE_START = 97;
const int UPPERCASE_START = 65;
const int DIGIT_START = 48;

/**
 * Get the possible characters that a string can have.
 */
void get_possible_values(char* values, int lowercase, int uppercase, int digits) {
    int i;
    int index = 0;
    if (lowercase) {
        for (i = LOWERCASE_START; i < LOWERCASE_START + 26; i++) {
            values[index] = i;
            index++;
        }
    }
    if (digits) {
        for (i = DIGIT_START; i < DIGIT_START + 10; i++) {
            values[index] = i;
            index++;
        }
    }
    if (uppercase) {
        for (i = UPPERCASE_START; i < UPPERCASE_START + 26; i++) {
            values[index] = i;
            index++;
        }
    }
}

/**
 * Bruteforce the string that results in the specified hash given the values
 * it can take on.
 */
int brute_force(char* guess, unsigned char* buffer, char* values,
                unsigned char* hash, int index, int maxIndex) {
    int i;
    for (i = 0; i < strlen(values); i++) {
        guess[index] = values[i];

        if (index == maxIndex) {
            sha256(guess, buffer);
            if (strncmp(buffer, hash, SHA256_DIGEST_LENGTH) == 0) {
                return 0;
            };
        } else {
            if (brute_force(guess, buffer, values, hash, index + 1, maxIndex) == 0) {
                return 0;
            }
        }
    }
    return -1;
}

int main (int argc, char **argv) {
    int lowercase = 0;
    int uppercase = 0;
    int digits = 0;
    int length = 0;

    int hash_arg = 0;
    char* pos;
    int i;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Parse arguments
    int c;
    while((c = getopt(argc, argv, "h:n:lud")) != -1) {
        switch(c) {
            case 'h':
                // Convert the hexidecimal string into a byte array
                pos = optarg;
                for (i = 0;  i < SHA256_DIGEST_LENGTH; i++) {
                    sscanf(pos, "%2hhx", &hash[i]);
                    pos += 2 * sizeof(char);
                }
                hash_arg = 1;
            case 'n':
                length = atoi(optarg);
                break;
            case 'l':
                lowercase = 1;
                break;
            case 'u':
                uppercase = 1;
                break;
            case 'd':
                digits = 1;
                break;
        }
    }

    // Check arguments
    if (length == 0 || hash_arg == 0 || (
                lowercase == 0 && uppercase == 0 && digits == 0)) {
        printf("Usage: ./main\n"
               "REQUIRED: -h (password hash) "
               "-n (password length)\n"
               "AT LEAST ONE: -l (contains lowercase) "
               "-u (contains uppercase) "
               "-d (contains digits)\n");
        return 1;
    }

    // Get the possible characters for the password
    int values_length = lowercase * 26 + uppercase * 26 + digits * 10 + 1;
    char values[values_length + 1];
    get_possible_values(values, lowercase, uppercase, digits);
    values[values_length] = '\0';

    // Create buffers
    char guess[length + 1];
    guess[length] = '\0';
    unsigned char buffer[SHA256_DIGEST_LENGTH];

    // Bruteforce the password and check how long it takes
    clock_t time = clock();
    int result = brute_force(guess, buffer, values, hash, 0, length - 1);
    time = clock() - time;

    if (result != 0) {
        printf("No password found\n");
        return 1;
    }
    printf("Password: %s\n", guess);
    printf("Time taken: %lu seconds\n", time / CLOCKS_PER_SEC);
    return 0;
}
