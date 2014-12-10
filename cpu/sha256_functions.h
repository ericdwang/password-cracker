void get_hash_hex(char* hex, unsigned char* hash);

void sha256(char guess[], int length, unsigned char buffer[], int iterations);

static const int SHA256_DIGEST_LENGTH = 32;
