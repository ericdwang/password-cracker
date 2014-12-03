#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "clhelp.h"


static const int GLOBAL_SIZE = 1 << 20;
static const int LOCAL_SIZE = 256;
static const int HASH_SIZE = 4;


int main(int argc, char *argv[]) {
    char hash[] = "test";
    char values[] = "qwertyasdf";
    int num_values = 10;
    int length = 4;

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

    // Allocate memory for the GPU
    cl_int err = CL_SUCCESS;
    cl_mem g_hash = clCreateBuffer(
            cv.context, CL_MEM_READ_ONLY, sizeof(char) * HASH_SIZE, &hash, &err);
    cl_mem g_values = clCreateBuffer(
            cv.context, CL_MEM_READ_ONLY, sizeof(char) * num_values, &values, &err);
    cl_mem g_found = clCreateBuffer(
            cv.context, CL_MEM_READ_WRITE, sizeof(int), NULL, &err);
    cl_mem g_password = clCreateBuffer(
            cv.context, CL_MEM_WRITE_ONLY, sizeof(char) * (length + 1), NULL, &err);
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
    err = clEnqueueNDRangeKernel(
            cv.commands, brute_force, 1, NULL,
            global_work_size, local_work_size, 0, NULL, NULL);
    CHK_ERR(err);

    // Read the password found on the GPU
    char password[length + 1];
    err = clEnqueueReadBuffer(
            cv.commands, g_password, true, 0,
            sizeof(char) * (length + 1), password, 0, NULL, NULL);
    CHK_ERR(err);
    printf("%s\n", password);

    // Read the found number
    int found[1];
    err = clEnqueueReadBuffer(
            cv.commands, g_found, true, 0,
            sizeof(int), found, 0, NULL, NULL);
    CHK_ERR(err);
    printf("%d\n", found[0]);

    // Reallocate memory
    uninitialize_ocl(cv);
    clReleaseMemObject(g_hash);
    clReleaseMemObject(g_values);
    clReleaseMemObject(g_found);
    clReleaseMemObject(g_password);

    return 0;
}
