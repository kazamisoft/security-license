#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

int main() 
{
    RSA *rsa;
    unsigned char plaintext[256], ciphertext[256], decrypted[256];
    int plaintext_len, ciphertext_len, decrypted_len;

    strcpy(plaintext, "Hello, world");
    // RSA 키 쌍 생성
    rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);

    // 암호화
    plaintext_len = sizeof(plaintext);
    ciphertext_len = RSA_public_encrypt(plaintext_len, plaintext, ciphertext, rsa, RSA_PKCS1_OAEP_PADDING);

    // 복호화
    decrypted_len = RSA_private_decrypt(ciphertext_len, ciphertext, decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    printf("decrypted_len=%d\n", decrypted_len);
    printf("decrypted=[%s]\n", decrypted);


    // RSA 키 쌍 해제
    RSA_free(rsa);

    return 0;
}
