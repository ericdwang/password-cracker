static __constant int HASH_SIZE = 4;

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
int check_guess(__constant char hash[], __local char guesses[], int guess_index) {
    int i;
    for (i = 0; i < HASH_SIZE; i++) {
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

    while (found[0] != size) {
        get_guess(values, guesses, guess_index, num_values, index, length);
        if (check_guess(hash, guesses, guess_index) == 0) {
            copy_guess(password, guesses, guess_index, length);
            found[0] = size;
        }
        index += size;
    }
}

