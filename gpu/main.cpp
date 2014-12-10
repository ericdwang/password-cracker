#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "clhelp.h"


// The ASCII printable characters are 32 to 126 (inclusive)
const int LOWERCASE_START = 97;
const int UPPERCASE_START = 65;
const int DIGIT_START = 48;
const int PUNCTUATION_START = 32;

// Sets of characters
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
int num_values;

// Length of the password
int min_length = 1;
int max_length = 5;

// Length of the hash
static const int SHA256_DIGEST_LENGTH = 32;
unsigned char hash[SHA256_DIGEST_LENGTH];

// Number of iterations to hash
int iterations = 1;

// Work sizes
static const int GLOBAL_SIZE = 1 << 12;
static const int LOCAL_SIZE = 1 << 7;

int main(int argc, char *argv[]) {
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
    char values[num_values + 1];
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
    values[num_values] = '\0';

    char password[max_length + 1];
    int found[1] = {0};

    // Set up and compile OpenCL kernels
    std::string brute_force_kernel_str;
    std::string brute_force_name_str = std::string("brute_force");
    std::string brute_force_kernel_file = std::string("brute_force.cl");
    cl_vars_t cv;
    cl_kernel brute_force;
    readFile(brute_force_kernel_file, brute_force_kernel_str);
    initialize_ocl(cv);
    compile_ocl_program(brute_force, cv, brute_force_kernel_str.c_str(),
            brute_force_name_str.c_str());

    // Allocate constants and global memory for the GPU
    cl_int err = CL_SUCCESS;
    cl_mem g_hash = clCreateBuffer(
            cv.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
            sizeof(char) * SHA256_DIGEST_LENGTH, &hash, &err);
    cl_mem g_values = clCreateBuffer(
            cv.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
            sizeof(char) * (num_values + 1), &values, &err);
    cl_mem g_found = clCreateBuffer(
            cv.context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
            sizeof(int), &found, &err);
    cl_mem g_password = clCreateBuffer(
            cv.context, CL_MEM_WRITE_ONLY,
            sizeof(char) * (max_length + 1), &password, &err);
    CHK_ERR(err);

    // Set global and local work sizes
    size_t global_work_size[1] = {GLOBAL_SIZE};
    size_t local_work_size[1] = {LOCAL_SIZE};

    // Set the arguments of the kernel
    err = clSetKernelArg(brute_force, 0, sizeof(cl_mem), &g_hash);
    CHK_ERR(err);
    err = clSetKernelArg(brute_force, 1, sizeof(cl_mem), &g_values);
    CHK_ERR(err);
    err = clSetKernelArg(brute_force, 2, sizeof(cl_mem), &g_found);
    CHK_ERR(err);
    err = clSetKernelArg(brute_force, 3, sizeof(cl_mem), &g_password);
    CHK_ERR(err);
    err = clSetKernelArg(brute_force, 4, sizeof(int), &num_values);
    CHK_ERR(err);
    err = clSetKernelArg(brute_force, 5, sizeof(int), &min_length);
    CHK_ERR(err);
    err = clSetKernelArg(brute_force, 6, sizeof(int), &max_length);
    CHK_ERR(err);
    err = clSetKernelArg(brute_force, 7, sizeof(int), &min_lowercase);
    CHK_ERR(err);
    err = clSetKernelArg(brute_force, 8, sizeof(int), &min_uppercase);
    CHK_ERR(err);
    err = clSetKernelArg(brute_force, 9, sizeof(int), &min_digits);
    CHK_ERR(err);
    err = clSetKernelArg(brute_force, 10, sizeof(int), &min_punctuation);
    CHK_ERR(err);
    err = clSetKernelArg(brute_force, 11, sizeof(int), &iterations);
    CHK_ERR(err);

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

    // Execute the kernel on the GPU
    double t0 = timestamp();
    err = clEnqueueNDRangeKernel(
            cv.commands, brute_force, 1, NULL,
            global_work_size, local_work_size, 0, NULL, NULL);
    CHK_ERR(err);

    // Read the password found on the GPU
    err = clEnqueueReadBuffer(
            cv.commands, g_password, true, 0,
            sizeof(char) * (max_length + 1), password, 0, NULL, NULL);
    CHK_ERR(err);

    t0 = timestamp() - t0;
    printf("Password: %s\n", password);
    printf("Time taken: %gs\n", t0);

    // Reallocate memory
    uninitialize_ocl(cv);
    clReleaseMemObject(g_hash);
    clReleaseMemObject(g_values);
    clReleaseMemObject(g_found);
    clReleaseMemObject(g_password);

    return 0;
}
