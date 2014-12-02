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
 * Get a guess given an index and the values it can take on.
 */
void get_guess(char* guess, char* values, int num_values, int index, int length) {
    int i;
    for (i = 0; i < length; i++) {
        guess[i] = values[index % num_values];
        index /= num_values;
    }
}

/**
 * Bruteforce the string that results in the specified hash given the values
 * it can take on.
 */
void brute_force(char* guess, unsigned char* hash, char* values, int num_values, int length) {
    unsigned char buffer[SHA256_DIGEST_LENGTH];
    int found = -1;
    int index;

    while (found != 0) {
        get_guess(guess, values, num_values, index, length);
        sha256(guess, buffer);
        found = strncmp(buffer, hash, SHA256_DIGEST_LENGTH);
        index++;
    }
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
    if (length == 0 || hash_arg == 0) {
        printf("Usage: ./main\n"
               "REQUIRED: -h (password hash) "
               "-n (password length)\n"
               "DEFAULT -lud unless specified: -l (contains lowercase) "
               "-u (contains uppercase) "
               "-d (contains digits)\n");
        return 1;
    }
    if (lowercase == 0 && uppercase == 0 && digits == 0) {
        lowercase = 1;
        uppercase = 1;
        digits = 1;
    }

    // Get the possible characters for the password
    int num_values = lowercase * 26 + uppercase * 26 + digits * 10;
    char values[num_values + 1];
    get_possible_values(values, lowercase, uppercase, digits);
    values[num_values] = '\0';

    // Create buffers
    char guess[length + 1];
    guess[length] = '\0';
    unsigned char buffer[SHA256_DIGEST_LENGTH];

    // Bruteforce the password and check how long it takes
    clock_t time = clock();
    brute_force(guess, hash, values, num_values, length);
    time = clock() - time;

    printf("Password: %s\n", guess);
    printf("Time taken: %lu seconds\n", time / CLOCKS_PER_SEC);
    return 0;
}
