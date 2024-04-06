#include <openssl/aes.h>
#include <openssl/rand.h>

int main() {
    unsigned char key[16], iv[16], plaintext[16], ciphertext[16];
    AES_KEY aes_key;

    // 키와 초기화 벡터(IV) 생성
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    // 암호화
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_cbc_encrypt(plaintext, ciphertext, sizeof(plaintext), &aes_key, iv, AES_ENCRYPT);

    // 복호화
    AES_cbc_encrypt(ciphertext, plaintext, sizeof(ciphertext), &aes_key, iv, AES_DECRYPT);

    return 0;
}
