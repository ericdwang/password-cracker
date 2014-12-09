#ifndef SHA256_H
#define SHA256_H
#include <string.h>
#include <array>


#define uint unsigned int

class SHA256
{
    public:
        SHA256();
        void Update(unsigned char * buffer, int length);
        void Finalize();
        void Digest(unsigned char * output);
    protected:
    private:
        uint rotl(const uint x, const uint y);
        uint rotr(const uint x, const uint y);
        uint Ch(const uint x, const uint y, const uint z);
        uint Maj(const uint x, const uint y, const uint z);
        uint S0(const uint x);
        uint S1(const uint x);
        uint s0(const uint x);
        uint s1(const uint x);
        uint bytereverse(const uint x);
        void sha256_transform(uint *state, uint *data);
        void sha256_block(const unsigned char * block);

        //unsigned int data[16];
        unsigned int state[8];
        unsigned int count_low, count_high;
        unsigned char block[64];
        unsigned int index;
        std::array<unsigned, 64> SHA256_K;
};

#endif // SHA256_H
