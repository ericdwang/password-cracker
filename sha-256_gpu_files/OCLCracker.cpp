#include "OCLCracker.h"

void contextError(const char *errinfo, const void *private_info, size_t cb, void *user_data)
{
    printf("\n**OpenCL error: %s\n", errinfo);
}

void CL_CALLBACK onOpenCLError(const char *errinfo,  const void *private_info, size_t cb, void *user_data)
{
    printf("Error while creating context or working in this context : %s", errinfo);
}

OCLCracker::OCLCracker()
{
    //ctor
}

OCLCracker::~OCLCracker()
{
    //dtor
}

void OCLCracker::Init()
{
    FILE *kf;
    size_t fsize;
    int i, x;
    uint data_in[128] = {0};
    uint results_out[32] = {0};
    int data_in_len = 128;
    int results_out_len = 32;
    int count = 1;
    int blocks_in_count = 2;

    memset(data_in, 0x30, sizeof(data_in));
    memcpy(data_in, "", 8);
    memset(data_in + 32, 0xee, 4 * 32);
    memset(results_out, 0, results_out_len * count);
    
    cl_uint             numEntries = 16;
    cl_platform_id*     platforms;          //List of platforms IDs
    cl_uint             numPlatforms = 1;       //The actual number of returned platform IDs
    cl_device_id*       device_id;
    cl_context          context;                 // compute context

    //Allocations
    platforms = (cl_platform_id*)malloc(sizeof(cl_platform_id)*numPlatforms);
    device_id = (cl_device_id*)malloc(numEntries*sizeof(cl_device_id));

    //We use the clGetPlatformIDs function
    err = clGetPlatformIDs(numPlatforms, platforms, &numPlatforms);
    if(err != CL_SUCCESS)
    {
        printf("Error while getting available platforms\n");
        exit(1);
    }

    // Connect to a compute device
    //
    int gpu = 1;
    err = clGetDeviceIDs(platforms[0], CL_DEVICE_TYPE_ALL, numEntries, device_id, &numEntries);
    if (err != CL_SUCCESS)
    {
        printf("Error: Failed to create a device group!\n");
        exit(1);
    }
    printf("Device Count: %d\n", numEntries);
    // Create a compute context
    //
    context = clCreateContext(0, 2, device_id, NULL, NULL, &err);
    if (!context)
    {
        printf("Error: Failed to create a compute context!\n");
        exit(1);
    }

    // Create a command commands
    //
    commands = clCreateCommandQueue(context, *device_id, 0, &err);
    if (!commands)
    {
        printf("Error: Failed to create a command commands!\n");
        exit(1);
    }

    // load kernel source
    kf = fopen("sha256.cl", "r");
    if(!kf)
    {
        printf("Error reading opencl program file");
    }
    fseek(kf , 0 , SEEK_END);
    fsize = ftell(kf);
    rewind(kf);
    char * KernelSource;
    KernelSource = (char *)malloc(fsize);
    fread(KernelSource, 1, fsize, kf);
    fclose(kf);
    printf("hello\n");

    //printf("%s", KernelSource);

    // Create the compute program from the source buffer
    //
    program = clCreateProgramWithSource(context, 1, (const char **) & KernelSource, NULL, &err);
    if (!program)
    {
        printf("Error: Failed to create compute program!\n");
        exit(1);
    }

    // Build the program executable
    //
    err = clBuildProgram(program, 0, NULL, "-w", NULL, NULL);
    size_t len;
    char buffer[2048];

    clGetProgramBuildInfo(program, *device_id, CL_PROGRAM_BUILD_LOG, sizeof(buffer), buffer, &len);
    printf("%s\n", buffer);
    if (err != CL_SUCCESS)
    {
        printf("Error: Failed to build program executable!\n");
        exit(1);
    }

    // Create the compute kernel in the program we wish to run
    //
    kernel = clCreateKernel(program, "test", &err);
    if (!kernel || err != CL_SUCCESS)
    {
        printf("Error: Failed to create compute kernel!\n");
        exit(1);
    }

    // Create the input and output arrays in device memory for our calculation
    //
    input = clCreateBuffer(context,  CL_MEM_READ_ONLY,  data_in_len * count, NULL, NULL);
    output = clCreateBuffer(context, CL_MEM_WRITE_ONLY, results_out_len * count, NULL, NULL);
    cl_mem iterations = clCreateBuffer(context, CL_MEM_READ_ONLY, sizeof(unsigned int), NULL, NULL);
    if (!input || !output)
    {
        printf("Error: Failed to allocate device memory!\n");
        exit(1);
    }

    // Write our data set into the input array in device memory
    //
    err = clEnqueueWriteBuffer(commands, input, CL_TRUE, 0, data_in_len * count, data_in, 0, NULL, NULL);
    if (err != CL_SUCCESS)
    {
        printf("Error: Failed to write to source array!\n");
        exit(1);
    }

    unsigned int iter = 2048;
    err = clEnqueueWriteBuffer(commands, iterations, CL_TRUE, 0, sizeof(unsigned int), &iter, 0, NULL, NULL);
    if (err != CL_SUCCESS)
    {
        printf("Error: Failed to write to source array!\n");
        exit(1);
    }

    // Set the arguments to our compute kernel
    //
    err = 0;
    err  = clSetKernelArg(kernel, 0, sizeof(input), &input);
    err |= clSetKernelArg(kernel, 1, sizeof(output), &output);
    err |= clSetKernelArg(kernel, 2, sizeof(iterations), &iterations);
    if (err != CL_SUCCESS)
    {
        printf("Error: Failed to set kernel arguments! %d\n", err);
        exit(1);
    }


    // Get the maximum work group size for executing the kernel on the device
    //
    err = clGetKernelWorkGroupInfo(kernel, *device_id, CL_KERNEL_WORK_GROUP_SIZE, sizeof(local), &local, NULL);
    if (err != CL_SUCCESS)
    {
        printf("Error: Failed to retrieve kernel work group info! %d\n", err);
        exit(1);
    }

    printf("CL_KERNEL_WORK_GROUP_SIZE : %d\n", (int)local);

    // Execute the kernel over the entire range of our 1d input data set
    // using the maximum number of work group items for this device
    //
    global = count;
    //global = 1;
    //printf("global = %d\n", global);
    //err = clEnqueueNDRangeKernel(commands, kernel, 1, NULL, &global, &local, 0, NULL, NULL);
    err = clEnqueueNDRangeKernel(commands, kernel, 1, NULL, &global, NULL, 0, NULL, NULL);
    if (err)
    {
        printf("Error: Failed to execute kernel (%d)!\n", err);
        exit(1);
    }

    // Wait for the command commands to get serviced before reading back results
    //
    clFinish(commands);

    // Read back the results from the device to verify the output
    //
    err = clEnqueueReadBuffer( commands, output, CL_TRUE, 0, results_out_len * count, results_out, 0, NULL, NULL );
    if (err != CL_SUCCESS)
    {
        printf("Error: Failed to read output array! %d\n", err);
        exit(1);
    }
    for (int i = 0; i < 32; ++i){
        printf("%02X", results_out[i]);
    }
}

void OCLCracker::CleanUp()
{
    // Shutdown and cleanup
    //
    clReleaseMemObject(input);
    clReleaseMemObject(output);
    clReleaseProgram(program);
    clReleaseKernel(kernel);
    clReleaseCommandQueue(commands);
    clReleaseContext(context);
}

int main(int argc, char** argv){
    OCLCracker holder; 
    holder.Init();
    return 0;
}
