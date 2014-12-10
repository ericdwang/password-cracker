#include <string.h>

static const int SHA256_DIGEST_LENGTH = 32;

static const int LOWERCASE_START = 97;
static const int DIGIT_START = 48;

const unsigned int SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

unsigned int rotl(const unsigned int x, const unsigned int y)
{
    return ( x<<y | x>>(32-y) );
}

unsigned int rotr(const unsigned int x, const unsigned int y)
{
    return ( x>>y | x<<(32-y) );
}

unsigned int Ch(const unsigned int x, const unsigned int y, const unsigned int z)
{
    return ( z ^ (x & ( y ^ z)) );
}
unsigned int Maj(const unsigned int x, const unsigned int y, const unsigned int z)
{
    return ( (x & y) | (z & (x | y)) );
}

unsigned int S0(const unsigned int x)
{
    return (rotr(x,2) ^ rotr(x,13) ^ rotr(x,22));
}
unsigned int S1(const unsigned int x)
{
    return (rotr(x,6) ^ rotr(x,11) ^ rotr(x,25));
}
unsigned int s0(const unsigned int x)
{
    return (rotr(x,7) ^ rotr(x,18) ^ (x>>3));
}
unsigned int s1(const unsigned int x)
{
    return (rotr(x,17) ^ rotr(x,19) ^ (x>>10));
}

unsigned int bytereverse(const unsigned int x)
{
    return ( ((x) << 24) | (((x) << 8) & 0x00ff0000) | (((x) >> 8) & 0x0000ff00) | ((x) >> 24) );
}

struct sha256_ctx
{
    unsigned int state[8];
    unsigned int count_low, count_high;
    unsigned char block[64];
    unsigned int index;
};

void sha256_init(struct sha256_ctx *ctx)
{
    ctx->state[0] = 0x6a09e667UL;
    ctx->state[1] = 0xbb67ae85UL;
    ctx->state[2] = 0x3c6ef372UL;
    ctx->state[3] = 0xa54ff53aUL;
    ctx->state[4] = 0x510e527fUL;
    ctx->state[5] = 0x9b05688cUL;
    ctx->state[6] = 0x1f83d9abUL;
    ctx->state[7] = 0x5be0cd19UL;
    ctx->count_low = ctx->count_high = 0;
    ctx->index = 0;
}

void sha256_transform(unsigned int *state, unsigned int *data)
{
    unsigned int W00,W01,W02,W03,W04,W05,W06,W07;
    unsigned int W08,W09,W10,W11,W12,W13,W14,W15;
    unsigned int T0,T1,T2,T3,T4,T5,T6,T7;

    T0 = state[0]; T1 = state[1];
    T2 = state[2]; T3 = state[3];
    T4 = state[4]; T5 = state[5];
    T6 = state[6]; T7 = state[7];

    //First Iteration
    T7 += S1( T4 ) + Ch( T4, T5, T6 ) + SHA256_K[0] + ( (W00 = data[0]) );
    T3 += T7;
    T7 += S0( T0 ) + Maj( T0, T1, T2 );

    T6 += S1( T3 ) + Ch( T3, T4, T5 ) + SHA256_K[1] + ( (W01 = data[1]) );
    T2 += T6;
    T6 += S0( T7 ) + Maj( T7, T0, T1 );

    T5 += S1( T2 ) + Ch( T2, T3, T4 ) + SHA256_K[2] + ( (W02 = data[2]) );
    T1 += T5;
    T5 += S0( T6 ) + Maj( T6, T7, T0 );

    T4 += S1( T1 ) + Ch( T1, T2, T3 ) + SHA256_K[3] + ( (W03 = data[3]) );
    T0 += T4;
    T4 += S0( T5 ) + Maj( T5, T6, T7 );

    T3 += S1( T0 ) + Ch( T0, T1, T2 ) + SHA256_K[4] + ( (W04 = data[4]) );
    T7 += T3;
    T3 += S0( T4 ) + Maj( T4, T5, T6 );

    T2 += S1( T7 ) + Ch( T7, T0, T1 ) + SHA256_K[5] + ( (W05 = data[5]) );
    T6 += T2;
    T2 += S0( T3 ) + Maj( T3, T4, T5 );

    T1 += S1( T6 ) + Ch( T6, T7, T0 ) + SHA256_K[6] + ( (W06 = data[6]) );
    T5 += T1;
    T1 += S0( T2 ) + Maj( T2, T3, T4 );

    T0 += S1( T5 ) + Ch( T5, T6, T7 ) + SHA256_K[7] + ( (W07 = data[7]) );
    T4 += T0;
    T0 += S0( T1 ) + Maj( T1, T2, T3 );

    T7 += S1( T4 ) + Ch( T4, T5, T6 ) + SHA256_K[8] + ( (W08 = data[8]) );
    T3 += T7;
    T7 += S0( T0 ) + Maj( T0, T1, T2 );

    T6 += S1( T3 ) + Ch( T3, T4, T5 ) + SHA256_K[9] + ( (W09 = data[9]) );
    T2 += T6;
    T6 += S0( T7 ) + Maj( T7, T0, T1 );

    T5 += S1( T2 ) + Ch( T2, T3, T4 ) + SHA256_K[10] + ( (W10 = data[10]) );
    T1 += T5;
    T5 += S0( T6 ) + Maj( T6, T7, T0 );

    T4 += S1( T1 ) + Ch( T1, T2, T3 ) + SHA256_K[11] + ( (W11 = data[11]) );
    T0 += T4;
    T4 += S0( T5 ) + Maj( T5, T6, T7 );

    T3 += S1( T0 ) + Ch( T0, T1, T2 ) + SHA256_K[12] + ( (W12 = data[12]) );
    T7 += T3;
    T3 += S0( T4 ) + Maj( T4, T5, T6 );

    T2 += S1( T7 ) + Ch( T7, T0, T1 ) + SHA256_K[13] + ( (W13 = data[13]) );
    T6 += T2;
    T2 += S0( T3 ) + Maj( T3, T4, T5 );

    T1 += S1( T6 ) + Ch( T6, T7, T0 ) + SHA256_K[14] + ( (W14 = data[14]) );
    T5 += T1;
    T1 += S0( T2 ) + Maj( T2, T3, T4 );

    T0 += S1( T5 ) + Ch( T5, T6, T7 ) + SHA256_K[15] + ( (W15 = data[15]) );
    T4 += T0;
    T0 += S0( T1 ) + Maj( T1, T2, T3 );



    T7 += S1( T4 ) + Ch( T4, T5, T6 ) + SHA256_K[16] + ( (W00 += s1( W14 ) + W09 + s0( W01 ) ) );
    T3 += T7;
    T7 += S0( T0 ) + Maj( T0, T1, T2 );

    T6 += S1( T3 ) + Ch( T3, T4, T5 ) + SHA256_K[17] + ( (W01 += s1( W15 ) + W10 + s0( W02 ) ) );
    T2 += T6;
    T6 += S0( T7 ) + Maj( T7, T0, T1 );

    T5 += S1( T2 ) + Ch( T2, T3, T4 ) + SHA256_K[18] + ( (W02 += s1( W00 ) + W11 + s0( W03 ) ) );
    T1 += T5;
    T5 += S0( T6 ) + Maj( T6, T7, T0 );

    T4 += S1( T1 ) + Ch( T1, T2, T3 ) + SHA256_K[19] + ( (W03 += s1( W01 ) + W12 + s0( W04 ) ) );
    T0 += T4;
    T4 += S0( T5 ) + Maj( T5, T6, T7 );

    T3 += S1( T0 ) + Ch( T0, T1, T2 ) + SHA256_K[20] + ( (W04 += s1( W02 ) + W13 + s0( W05 ) ) );
    T7 += T3;
    T3 += S0( T4 ) + Maj( T4, T5, T6 );

    T2 += S1( T7 ) + Ch( T7, T0, T1 ) + SHA256_K[21] + ( (W05 += s1( W03 ) + W14 + s0( W06 ) ) );
    T6 += T2;
    T2 += S0( T3 ) + Maj( T3, T4, T5 );

    T1 += S1( T6 ) + Ch( T6, T7, T0 ) + SHA256_K[22] + ( (W06 += s1( W04 ) + W15 + s0( W07 ) ) );
    T5 += T1;
    T1 += S0( T2 ) + Maj( T2, T3, T4 );

    T0 += S1( T5 ) + Ch( T5, T6, T7 ) + SHA256_K[23] + ( (W07 += s1( W05 ) + W00 + s0( W08 ) ) );
    T4 += T0;
    T0 += S0( T1 ) + Maj( T1, T2, T3 );

    T7 += S1( T4 ) + Ch( T4, T5, T6 ) + SHA256_K[24] + ( (W08 += s1( W06 ) + W01 + s0( W09 ) ) );
    T3 += T7;
    T7 += S0( T0 ) + Maj( T0, T1, T2 );

    T6 += S1( T3 ) + Ch( T3, T4, T5 ) + SHA256_K[25] + ( (W09 += s1( W07 ) + W02 + s0( W10 ) ) );
    T2 += T6;
    T6 += S0( T7 ) + Maj( T7, T0, T1 );

    T5 += S1( T2 ) + Ch( T2, T3, T4 ) + SHA256_K[26] + ( (W10 += s1( W08 ) + W03 + s0( W11 ) ) );
    T1 += T5;
    T5 += S0( T6 ) + Maj( T6, T7, T0 );

    T4 += S1( T1 ) + Ch( T1, T2, T3 ) + SHA256_K[27] + ( (W11 += s1( W09 ) + W04 + s0( W12 ) ) );
    T0 += T4;
    T4 += S0( T5 ) + Maj( T5, T6, T7 );

    T3 += S1( T0 ) + Ch( T0, T1, T2 ) + SHA256_K[28] + ( (W12 += s1( W10 ) + W05 + s0( W13 ) ) );
    T7 += T3;
    T3 += S0( T4 ) + Maj( T4, T5, T6 );

    T2 += S1( T7 ) + Ch( T7, T0, T1 ) + SHA256_K[29] + ( (W13 += s1( W11 ) + W06 + s0( W14 ) ) );
    T6 += T2;
    T2 += S0( T3 ) + Maj( T3, T4, T5 );

    T1 += S1( T6 ) + Ch( T6, T7, T0 ) + SHA256_K[30] + ( (W14 += s1( W12 ) + W07 + s0( W15 ) ) );
    T5 += T1;
    T1 += S0( T2 ) + Maj( T2, T3, T4 );

    T0 += S1( T5 ) + Ch( T5, T6, T7 ) + SHA256_K[31] + ( (W15 += s1( W13 ) + W08 + s0( W00 ) ) );
    T4 += T0;
    T0 += S0( T1 ) + Maj( T1, T2, T3 );




    T7 += S1( T4 ) + Ch( T4, T5, T6 ) + SHA256_K[32] + ( (W00 += s1( W14 ) + W09 + s0( W01 ) ) );
    T3 += T7;
    T7 += S0( T0 ) + Maj( T0, T1, T2 );

    T6 += S1( T3 ) + Ch( T3, T4, T5 ) + SHA256_K[33] + ( (W01 += s1( W15 ) + W10 + s0( W02 ) ) );
    T2 += T6;
    T6 += S0( T7 ) + Maj( T7, T0, T1 );

    T5 += S1( T2 ) + Ch( T2, T3, T4 ) + SHA256_K[34] + ( (W02 += s1( W00 ) + W11 + s0( W03 ) ) );
    T1 += T5;
    T5 += S0( T6 ) + Maj( T6, T7, T0 );

    T4 += S1( T1 ) + Ch( T1, T2, T3 ) + SHA256_K[35] + ( (W03 += s1( W01 ) + W12 + s0( W04 ) ) );
    T0 += T4;
    T4 += S0( T5 ) + Maj( T5, T6, T7 );

    T3 += S1( T0 ) + Ch( T0, T1, T2 ) + SHA256_K[36] + ( (W04 += s1( W02 ) + W13 + s0( W05 ) ) );
    T7 += T3;
    T3 += S0( T4 ) + Maj( T4, T5, T6 );

    T2 += S1( T7 ) + Ch( T7, T0, T1 ) + SHA256_K[37] + ( (W05 += s1( W03 ) + W14 + s0( W06 ) ) );
    T6 += T2;
    T2 += S0( T3 ) + Maj( T3, T4, T5 );

    T1 += S1( T6 ) + Ch( T6, T7, T0 ) + SHA256_K[38] + ( (W06 += s1( W04 ) + W15 + s0( W07 ) ) );
    T5 += T1;
    T1 += S0( T2 ) + Maj( T2, T3, T4 );

    T0 += S1( T5 ) + Ch( T5, T6, T7 ) + SHA256_K[39] + ( (W07 += s1( W05 ) + W00 + s0( W08 ) ) );
    T4 += T0;
    T0 += S0( T1 ) + Maj( T1, T2, T3 );

    T7 += S1( T4 ) + Ch( T4, T5, T6 ) + SHA256_K[40] + ( (W08 += s1( W06 ) + W01 + s0( W09 ) ) );
    T3 += T7;
    T7 += S0( T0 ) + Maj( T0, T1, T2 );

    T6 += S1( T3 ) + Ch( T3, T4, T5 ) + SHA256_K[41] + ( (W09 += s1( W07 ) + W02 + s0( W10 ) ) );
    T2 += T6;
    T6 += S0( T7 ) + Maj( T7, T0, T1 );

    T5 += S1( T2 ) + Ch( T2, T3, T4 ) + SHA256_K[42] + ( (W10 += s1( W08 ) + W03 + s0( W11 ) ) );
    T1 += T5;
    T5 += S0( T6 ) + Maj( T6, T7, T0 );

    T4 += S1( T1 ) + Ch( T1, T2, T3 ) + SHA256_K[43] + ( (W11 += s1( W09 ) + W04 + s0( W12 ) ) );
    T0 += T4;
    T4 += S0( T5 ) + Maj( T5, T6, T7 );

    T3 += S1( T0 ) + Ch( T0, T1, T2 ) + SHA256_K[44] + ( (W12 += s1( W10 ) + W05 + s0( W13 ) ) );
    T7 += T3;
    T3 += S0( T4 ) + Maj( T4, T5, T6 );

    T2 += S1( T7 ) + Ch( T7, T0, T1 ) + SHA256_K[45] + ( (W13 += s1( W11 ) + W06 + s0( W14 ) ) );
    T6 += T2;
    T2 += S0( T3 ) + Maj( T3, T4, T5 );

    T1 += S1( T6 ) + Ch( T6, T7, T0 ) + SHA256_K[46] + ( (W14 += s1( W12 ) + W07 + s0( W15 ) ) );
    T5 += T1;
    T1 += S0( T2 ) + Maj( T2, T3, T4 );

    T0 += S1( T5 ) + Ch( T5, T6, T7 ) + SHA256_K[47] + ( (W15 += s1( W13 ) + W08 + s0( W00 ) ) );
    T4 += T0;
    T0 += S0( T1 ) + Maj( T1, T2, T3 );




    T7 += S1( T4 ) + Ch( T4, T5, T6 ) + SHA256_K[48] + ( (W00 += s1( W14 ) + W09 + s0( W01 ) ) );
    T3 += T7;
    T7 += S0( T0 ) + Maj( T0, T1, T2 );

    T6 += S1( T3 ) + Ch( T3, T4, T5 ) + SHA256_K[49] + ( (W01 += s1( W15 ) + W10 + s0( W02 ) ) );
    T2 += T6;
    T6 += S0( T7 ) + Maj( T7, T0, T1 );

    T5 += S1( T2 ) + Ch( T2, T3, T4 ) + SHA256_K[50] + ( (W02 += s1( W00 ) + W11 + s0( W03 ) ) );
    T1 += T5;
    T5 += S0( T6 ) + Maj( T6, T7, T0 );

    T4 += S1( T1 ) + Ch( T1, T2, T3 ) + SHA256_K[51] + ( (W03 += s1( W01 ) + W12 + s0( W04 ) ) );
    T0 += T4;
    T4 += S0( T5 ) + Maj( T5, T6, T7 );

    T3 += S1( T0 ) + Ch( T0, T1, T2 ) + SHA256_K[52] + ( (W04 += s1( W02 ) + W13 + s0( W05 ) ) );
    T7 += T3;
    T3 += S0( T4 ) + Maj( T4, T5, T6 );

    T2 += S1( T7 ) + Ch( T7, T0, T1 ) + SHA256_K[53] + ( (W05 += s1( W03 ) + W14 + s0( W06 ) ) );
    T6 += T2;
    T2 += S0( T3 ) + Maj( T3, T4, T5 );

    T1 += S1( T6 ) + Ch( T6, T7, T0 ) + SHA256_K[54] + ( (W06 += s1( W04 ) + W15 + s0( W07 ) ) );
    T5 += T1;
    T1 += S0( T2 ) + Maj( T2, T3, T4 );

    T0 += S1( T5 ) + Ch( T5, T6, T7 ) + SHA256_K[55] + ( (W07 += s1( W05 ) + W00 + s0( W08 ) ) );
    T4 += T0;
    T0 += S0( T1 ) + Maj( T1, T2, T3 );

    T7 += S1( T4 ) + Ch( T4, T5, T6 ) + SHA256_K[56] + ( (W08 += s1( W06 ) + W01 + s0( W09 ) ) );
    T3 += T7;
    T7 += S0( T0 ) + Maj( T0, T1, T2 );

    T6 += S1( T3 ) + Ch( T3, T4, T5 ) + SHA256_K[57] + ( (W09 += s1( W07 ) + W02 + s0( W10 ) ) );
    T2 += T6;
    T6 += S0( T7 ) + Maj( T7, T0, T1 );

    T5 += S1( T2 ) + Ch( T2, T3, T4 ) + SHA256_K[58] + ( (W10 += s1( W08 ) + W03 + s0( W11 ) ) );
    T1 += T5;
    T5 += S0( T6 ) + Maj( T6, T7, T0 );

    T4 += S1( T1 ) + Ch( T1, T2, T3 ) + SHA256_K[59] + ( (W11 += s1( W09 ) + W04 + s0( W12 ) ) );
    T0 += T4;
    T4 += S0( T5 ) + Maj( T5, T6, T7 );

    T3 += S1( T0 ) + Ch( T0, T1, T2 ) + SHA256_K[60] + ( (W12 += s1( W10 ) + W05 + s0( W13 ) ) );
    T7 += T3;
    T3 += S0( T4 ) + Maj( T4, T5, T6 );

    T2 += S1( T7 ) + Ch( T7, T0, T1 ) + SHA256_K[61] + ( (W13 += s1( W11 ) + W06 + s0( W14 ) ) );
    T6 += T2;
    T2 += S0( T3 ) + Maj( T3, T4, T5 );

    T1 += S1( T6 ) + Ch( T6, T7, T0 ) + SHA256_K[62] + ( (W14 += s1( W12 ) + W07 + s0( W15 ) ) );
    T5 += T1;
    T1 += S0( T2 ) + Maj( T2, T3, T4 );

    T0 += S1( T5 ) + Ch( T5, T6, T7 ) + SHA256_K[63] + ( (W15 += s1( W13 ) + W08 + s0( W00 ) ) );
    T4 += T0;
    T0 += S0( T1 ) + Maj( T1, T2, T3 );

    state[0] += T0;
    state[1] += T1;
    state[2] += T2;
    state[3] += T3;
    state[4] += T4;
    state[5] += T5;
    state[6] += T6;
    state[7] += T7;
}

void sha256_block(struct sha256_ctx *ctx, const unsigned char *block)
{
    unsigned int data[16];
    int i;

    if (!++ctx->count_low)
        ++ctx->count_high;

    for (i = 0; i < 16; i++, block += 4)
        data[i] = (*(block) << 24) | (*(block + 1) << 16) | (*(block + 2) << 8) | (*(block + 3));

    sha256_transform(ctx->state, data);
}

void sha256_update(struct sha256_ctx *ctx, const unsigned char *buffer, unsigned length)
{
    if (ctx->index)
    {
        unsigned left = 64 - ctx->index;
        if (length < left)
        {
            memcpy(ctx->block + ctx->index, buffer, length);
            ctx->index += length;
            return;
        }
        else
        {
            memcpy(ctx->block + ctx->index, buffer, left);
            sha256_block(ctx, ctx->block);
            buffer += left;
            length -= left;
        }
    }
    while (length >= 64)
    {
        sha256_block(ctx, buffer);
        buffer += 64;
        length -= 64;
    }
    memcpy(ctx->block, buffer, length);
    ctx->index = length;
}

void sha256_final(struct sha256_ctx *ctx)
{
    unsigned int data[16];
    int i;
    int words;

    i = ctx->index;

    ctx->block[i++] = 0x80;

    for (; i & 3; i++) ctx->block[i] = 0;

    words = i >> 2;
    for (i = 0; i < words; i++) data[i] = (*((ctx->block + 4 * i)) << 24) | (*((ctx->block + 4 * i) + 1) << 16) | (*((ctx->block + 4 * i) + 2) << 8) | (*((ctx->block + 4 * i) + 3));

    if (words > (16 - 2))
    {
        for (i = words; i < 16; i++) data[i] = 0;
        sha256_transform(ctx->state, data);
        for (i = 0; i < (16 - 2); i++) data[i] = 0;
    }
    else
    {
        for (i = words; i < 16 - 2; i++) data[i] = 0;
    }

    data[16 - 2] = (ctx->count_high << 9) | (ctx->count_low >> 23);
    data[16 - 1] = (ctx->count_low << 9) | (ctx->index << 3);
    sha256_transform(ctx->state, data);
}

void sha256_digest(const struct sha256_ctx *ctx, unsigned char *s)
{
    int i;

    if (s != 0)
    {
        for (i = 0; i < 8; i++)
        {
            *s++ = ctx->state[i] >> 24;
            *s++ = 0xff & (ctx->state[i] >> 16);
            *s++ = 0xff & (ctx->state[i] >> 8);
            *s++ = 0xff & ctx->state[i];
        }
    }
}

/**
 * Convert a decimal number to hexidecimal.
 */
int to_hex(int number) {
    if (number < 10) {
        return number + DIGIT_START;
    } else {
        return number + LOWERCASE_START - 10;
    }
}

/**
 * Get the hexidecimal representation of a hash stored in an unsigned char
 * array.
 */
void get_hash_hex(char* hex, unsigned char* hash) {
    int i;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        int value = hash[i];
        hex[i * 2 + 1] = to_hex(value % 16);
        hex[i * 2] = to_hex(value / 16);
    }
    hex[64] = 0;
}

/**
 * Compute the SHA-256 hash of a string for a number of iterations and write
 * it to a buffer.
 */
void sha256(char guess[], int length, unsigned char buffer[], int iterations) {
    struct sha256_ctx hdc;
    sha256_init(&hdc);
    sha256_update(&hdc, (unsigned char*) guess, length);
    sha256_final(&hdc);
    sha256_digest(&hdc, buffer);
    int i;
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
	for (i = 1; i < iterations; i++) {
        get_hash_hex(hex, buffer);
        sha256_init(&hdc);
        sha256_update(&hdc, (unsigned char*) hex, SHA256_DIGEST_LENGTH * 2);
        sha256_final(&hdc);
        sha256_digest(&hdc, buffer);
    }
}
