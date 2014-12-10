static __constant int LOWERCASE_START = 97;
static __constant int UPPERCASE_START = 65;
static __constant int DIGIT_START = 48;
static __constant int PUNCTUATION_START = 32;

static __constant int SHA256_DIGEST_LENGTH = 32;

/*
 * Generate a guess given an index and the values it can take on.
 */
void get_guess(
        __constant char values[],
        __local char guesses[],
        int guess_index,
        int num_values,
        ulong index,
        int length) {
    int i;
    for (i = 0; i < length; i++) {
        guesses[guess_index + i] = values[index % num_values];
        index /= num_values;
    }
}

/**
 * Check whether a password is valid according to the minimum number of
 * characters for each type.
 */
int valid_guess(
        __local char guesses[],
        int guess_index,
        int length,
        int min_lowercase,
        int min_uppercase,
        int min_digits,
        int min_punctuation
        ) {
    int num_lowercase = 0;
    int num_uppercase = 0;
    int num_digits = 0;
    int num_punctuation = 0;

    int i;
    for (i = 0; i < length; i++) {
        int curr = guesses[guess_index + i];
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

/*
 * Check a guess against a hash.
 */
int check_guess(__constant char hash[], __local char guesses[], int guess_index, int length) {
    int i;
    // TODO: Use actual hash length
    for (i = 0; i < length; i++) {
        if (guesses[guess_index + i] != hash[i]) {
            return -1;
        }
    }
    return 0;
}

/**
 * Copy the guess to global memory to be read on the CPU.
 */
void copy_guess(
        __global char password[], __local char guesses[], int guess_index,
        int length) {
    int i;
    for (i = 0; i < length; i++) {
        password[i] = guesses[guess_index + i];
    }
    password[length] = '\0';
}

/**
 * Brute force a password, doing guesses in parallel.
 */
__kernel void brute_force(
        __constant char hash[],
        __constant char values[],
        __global int found[],
        __global char password[],
        __local char guesses[],
        int num_values,
        int length,
        int min_lowercase,
        int min_uppercase,
        int min_digits,
        int min_punctuation
        ) {
    ulong index = get_global_id(0);
    int size = get_global_size(0);
    int guess_index = get_local_id(0) * length;

    int status = 0;
    while (!status) {
        get_guess(values, guesses, guess_index, num_values, index, length);
        if (!valid_guess(guesses, guess_index, length, min_lowercase,
                    min_uppercase, min_digits, min_punctuation)) {
            continue;
        }
        if (check_guess(hash, guesses, guess_index, length) == 0) {
            copy_guess(password, guesses, guess_index, length);
            // Notify the other work-items to stop
            found[0] = 1;
            break;
        }
        index += size;
        status = found[0];
    }
}
