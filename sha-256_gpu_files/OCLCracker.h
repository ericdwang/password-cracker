#ifndef OCLCRACKER_H
#define OCLCRACKER_H
#include <CL/cl.h>
#include <stdio.h>
#include <queue>
#include <string.h>

using namespace std;

#define HASH_SIZE 32

#define uint unsigned int

class OCLCracker
{
    public:
        OCLCracker();
        void Init();
        void CleanUp();
        virtual ~OCLCracker();


    protected:
    private:
        unsigned char * data_in;            // Data to be moved into the device memory
        unsigned char * results_out;        // Data extracted from the device memory
        int err;                            // error code returned from api calls
        unsigned int correct;               // number of correct results returned
        size_t global;                      // global domain size for our calculation
        size_t local;                       // local domain size for our calculation

        cl_device_id device_id;             // compute device id
        cl_context context;                 // compute context
        cl_command_queue commands;          // compute command queue
        cl_program program;                 // compute program
        cl_kernel kernel;                   // compute kernel

        cl_mem input;                       // device memory used for the input array
        cl_mem output;                      // device memory used for the output array
};

#endif // OCLCRACKER_H
