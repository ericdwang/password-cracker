#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <omp.h>
#include <openssl/sha.h>

#include "sha256_functions.h"


// The ASCII printable characters are 32 to 126 (inclusive)
const int LOWERCASE_START = 97;
const int UPPERCASE_START = 65;
const int DIGIT_START = 48;
const int PUNCTUATION_START = 32;

// Whether the password contains these types of characters
int lowercase = 0;
int uppercase = 0;
int digits = 0;
int punctuation = 0;

// Minimum number of characters for each type
int min_lowercase = 0;
int min_uppercase = 0;
int min_digits = 0;
int min_punctuation = 0;

// The possible values that the password can take on
char* values;
int num_values;

// The hash of the password to crack
unsigned char hash[SHA256_DIGEST_LENGTH];
// Length of the password
int min_length = 1;
int max_length = 5;

// Number of iterations to hash
int iterations = 1;

char* password;

/**
 * Get a timestamp.
 */
double timestamp() {
    struct timeval tv;
    gettimeofday(&tv, 0);
    return tv.tv_sec + 1e-6*tv.tv_usec;
}

/**
 * Raise a base to a power.
 */
unsigned long long ipow(int base, int exp) {
    unsigned long long result = 1ULL;
    while (exp) {
        if (exp & 1) {
            result *= (unsigned long long) base;
        }
        exp >>= 1;
        base *= base;
    }
    return result;
}

/**
 * Get the possible characters that a string can have.
 */
void get_possible_values() {
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
    if (punctuation) {
        for (i = PUNCTUATION_START; i < PUNCTUATION_START + 16; i++) {
            values[index] = i;
            index++;
        }
    }
}

/**
 * Get a guess given an index and the values it can take on.
 */
void get_guess(char guess[], unsigned long long index, int length) {
    int i;
    for (i = 0; i < length; i++) {
        guess[i] = values[index % num_values];
        index /= num_values;
    }
}

/**
 * Check whether a password is valid according to the minimum number of
 * characters for each type.
 */
int valid_guess(char guess[], int length) {
    int num_lowercase = 0;
    int num_uppercase = 0;
    int num_digits = 0;
    int num_punctuation = 0;

    int i;
    for (i = 0; i < length; i++) {
        int curr = guess[i];
        num_lowercase += (curr >= LOWERCASE_START &&
                curr < LOWERCASE_START + 26);
        num_uppercase += (curr >= UPPERCASE_START &&
                curr < UPPERCASE_START + 26);
        num_digits += (curr >= DIGIT_START &&
                curr < DIGIT_START + 10);
        num_punctuation += (curr >= PUNCTUATION_START &&
                curr < PUNCTUATION_START + 16);
    }
    return (num_lowercase >= min_lowercase &&
            num_uppercase >= min_uppercase &&
            num_digits >= min_digits &&
            num_punctuation >= min_punctuation);
}

/**
 * Bruteforce the string that results in the specified hash given the values
 * it can take on.
 */
void brute_force() {
    int length;
    int found = 0;

    for (length = min_length; length <= max_length && !found; length++) {
        unsigned long long max_guesses = ipow(num_values, length);
        unsigned char buffer[SHA256_DIGEST_LENGTH];
        char guess[length + 1];
        guess[length] = '\0';

        # pragma omp parallel for private(buffer) private(guess)
        for (unsigned long long index = 0; index < max_guesses; index++) {
            if (found) {
                continue;
            }
            get_guess(guess, index, length);
            if (!valid_guess(guess, length)) {
                continue;
            }
            sha256(guess, buffer, iterations);
            if (memcmp(buffer, hash, SHA256_DIGEST_LENGTH) == 0) {
                memcpy(password, guess, length + 1);
                found = 1;
            }
        }
    }
}

int main (int argc, char **argv) {
    int hash_arg = 0;
    char* pos;
    int i;

    // Parse arguments
    int c;
    while((c = getopt(argc, argv, "h:m:n:l:u:d:p:i:")) != -1) {
        switch(c) {
            case 'h':
                // Convert the hexidecimal string into a byte array
                pos = optarg;
                for (i = 0;  i < SHA256_DIGEST_LENGTH; i++) {
                    sscanf(pos, "%2hhx", &hash[i]);
                    pos += 2 * sizeof(char);
                }
                hash_arg = 1;
                break;
            case 'm':
                min_length = atoi(optarg);
                break;
            case 'n':
                max_length = atoi(optarg);
                break;
            case 'l':
                min_lowercase = atoi(optarg);
                lowercase = 1;
                break;
            case 'u':
                min_uppercase = atoi(optarg);
                uppercase = 1;
                break;
            case 'd':
                min_digits = atoi(optarg);
                digits = 1;
                break;
            case 'p':
                min_punctuation = atoi(optarg);
                punctuation = 1;
                break;
            case 'i':
                iterations = atoi(optarg);
                break;
        }
    }

    // Check arguments
    if (!hash_arg) {
        printf("Usage: ./main\n"
                "REQUIRED: -h (password hash)\n"
                "OPTIONAL (default 1-5 characters, all possible types, 1 iteration):\n"
                "-m (min password length)\n"
                "-n (max password length)\n"
                "-l (min lowercase characters)\n"
                "-u (min uppercase characters)\n"
                "-d (min digits characters)\n"
                "-p (min punctuation characters)\n"
                "-i (number of iterations to hash)\n"
                );
        return 1;
    }
    if (!lowercase && !uppercase && !digits && !punctuation) {
        lowercase = 1;
        uppercase = 1;
        digits = 1;
        punctuation = 1;
    }

    // Get the possible characters for the password
    num_values = lowercase * 26 + uppercase * 26 + digits * 10 + punctuation * 16;
    values = (char*) malloc((num_values + 1) * sizeof(char));
    get_possible_values();
    values[num_values] = '\0';

    // Create guess buffer
    password = (char*) malloc((max_length + 1) * sizeof(char));

    printf("Cracking password with %d to %d characters with %d iterations containing:\n",
            min_length, max_length, iterations);
    if (lowercase) {
        printf("At least %d lowercase characters\n", min_lowercase);
    } else {
        printf("No lowercase characters\n");
    }
    if (uppercase) {
        printf("At least %d uppercase characters\n", min_uppercase);
    } else {
        printf("No uppercase characters\n");
    }
    if (digits) {
        printf("At least %d digits characters\n", min_digits);
    } else {
        printf("No digits characters\n");
    }
    if (punctuation) {
        printf("At least %d punctuation characters\n", min_punctuation);
    } else {
        printf("No punctuation characters\n");
    }

    // Bruteforce the password and check how long it takes
    double t0 = timestamp();
    brute_force();
    t0 = timestamp() - t0;

    printf("Password: %s\n", password);
    printf("Time taken: %gs\n", t0);
    return 0;
}
