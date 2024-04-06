#include <openssl/sha.h>

int main() {
    unsigned char input[] = "Hello, World!";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int i;

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input, strlen((char *)input));
    SHA256_Final(hash, &ctx);

    printf("SHA-256 hash: ");
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}
