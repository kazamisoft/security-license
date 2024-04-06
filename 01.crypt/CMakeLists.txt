cmake_minimum_required(VERSION 3.0)
project(crypto_examples C)

find_package(OpenSSL REQUIRED)

# AES-128 암호화 알고리즘
add_executable(aes_example aes_example.c)
target_link_libraries(aes_example OpenSSL::Crypto)

# RSA-2048 암호화 알고리즘 
add_executable(rsa_example rsa_example.c)
target_link_libraries(rsa_example OpenSSL::Crypto)

# SHA-256 해시 함수
add_executable(sha256_example sha256_example.c)
target_link_libraries(sha256_example OpenSSL::Crypto)
