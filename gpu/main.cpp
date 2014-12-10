#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "clhelp.h"


// The ASCII printable characters are 32 to 126 (inclusive)
const int LOWERCASE_START = 97;
const int UPPERCASE_START = 65;
const int DIGIT_START = 48;

// Sets of characters
int lowercase = 0;
int uppercase = 0;
int digits = 0;

// The possible values that the password can take on
int num_values;

// Length of the password
int length = 0;
// Length of the hash
static const int SHA256_DIGEST_LENGTH = 32;
char hash[SHA256_DIGEST_LENGTH];

// Work sizes
static const int GLOBAL_SIZE = 1 << 14;
static const int LOCAL_SIZE = 512;

int main(int argc, char *argv[]) {
    int hash_arg = 0;
    char* pos;
    int i;

    // Parse arguments
    int c;
    while((c = getopt(argc, argv, "h:n:lud")) != -1) {
        switch(c) {
            case 'h':
                // TODO: Read in actual hash
                strcpy(hash, optarg);
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
    num_values = lowercase * 26 + uppercase * 26 + digits * 10;
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
    values[num_values] = '\0';

    char password[length + 1];
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
            sizeof(char) * (length + 1), &password, &err);
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
    err = clSetKernelArg(brute_force, 4, sizeof(char) * (length * LOCAL_SIZE), NULL);
    CHK_ERR(err);
    err = clSetKernelArg(brute_force, 5, sizeof(int), &num_values);
    CHK_ERR(err);
    err = clSetKernelArg(brute_force, 6, sizeof(int), &length);
    CHK_ERR(err);

    // Execute the kernel on the GPU
    double t0 = timestamp();
    err = clEnqueueNDRangeKernel(
            cv.commands, brute_force, 1, NULL,
            global_work_size, local_work_size, 0, NULL, NULL);
    CHK_ERR(err);

    // Read the password found on the GPU
    err = clEnqueueReadBuffer(
            cv.commands, g_password, true, 0,
            sizeof(char) * (length + 1), password, 0, NULL, NULL);
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
