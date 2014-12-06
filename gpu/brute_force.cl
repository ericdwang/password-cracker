static __constant int SHA256_DIGEST_LENGTH = 32;

/*
 * Generate a guess given an index and the values it can take on.
 */
void get_guess(
        __constant char values[],
        __local char guesses[],
        int guess_index,
        int num_values,
        int index,
        int length) {
    int i;
    for (i = 0; i < length; i++) {
        guesses[guess_index + i] = values[index % num_values];
        index /= num_values;
    }
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
        int length) {
    int index = get_global_id(0);
    int size = get_global_size(0);
    int guess_index = get_local_id(0) * length;

    int status = 0;
    while (status != 1) {
        get_guess(values, guesses, guess_index, num_values, index, length);
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
