#include <stdexcept>
#include <iomanip>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "common.hpp"
#include "gcm.hpp"


std::vector<unsigned char>
derive_key(const std::vector<unsigned char>& passphrase, const std::vector<unsigned char>& salt)
{
    const int ITERATIONS = 100000;
    const int KEY_LENGTH = 32; // 256 bits for AES-256
    std::vector<unsigned char> key(KEY_LENGTH);

    if (PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(passphrase.data()), passphrase.size(),
                          salt.data(), salt.size(), ITERATIONS,
                          EVP_sha256(), KEY_LENGTH, key.data()) != 1) {
        throw std::runtime_error("Key derivation failed.");
    }
    return key;
}

std::vector<unsigned char>
encrypt_gcm_bin(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ciphertext_len = 0;

    std::vector<unsigned char> salt = generate_random(16);
    std::vector<unsigned char> nonce = generate_random(12);

    std::vector<unsigned char> key = derive_key(passphrase, salt);

    std::vector<unsigned char> ciphertext_buffer(data.size() + EVP_MAX_IV_LENGTH);
    std::vector<unsigned char> tag(16);

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed.");
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed.");
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl (IVLEN) failed.");
    }

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex (key/IV) failed.");
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext_buffer.data(), &len, data.data(), data.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed.");
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext_buffer.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed.");
    }
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl (GET_TAG) failed.");
    }

    EVP_CIPHER_CTX_free(ctx);

    std::vector<unsigned char> result;
    result.insert(result.end(), salt.begin(), salt.end());
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext_buffer.begin(), ciphertext_buffer.begin() + ciphertext_len);
    result.insert(result.end(), tag.begin(), tag.end());

    return result;
}

std::vector<unsigned char>
decrypt_gcm_bin(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int plaintext_len = 0;

    if (data.size() < (16 + 12 + 16)) {
        throw std::runtime_error("Encrypted data is too short.");
    }

    std::vector<unsigned char> salt(data.begin(), data.begin() + 16);
    std::vector<unsigned char> nonce(data.begin() + 16, data.begin() + 28);
    std::vector<unsigned char> tag(data.end() - 16, data.end());
    std::vector<unsigned char> ciphertext(data.begin() + 28, data.end() - 16);

    std::vector<unsigned char> key = derive_key(passphrase, salt);

    std::vector<unsigned char> plaintext_buffer(ciphertext.size() + EVP_MAX_IV_LENGTH);

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed.");
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed.");
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl (IVLEN) failed.");
    }

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex (key/IV) failed.");
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext_buffer.data(), &len, ciphertext.data(), ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed.");
    }
    plaintext_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl (SET_TAG) failed.");
    }

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext_buffer.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        // This is where GCM authentication failure is typically caught
        // You might want to get OpenSSL error strings here for more detail
        throw std::runtime_error("Authentication failed or decryption error.");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::vector<unsigned char>(plaintext_buffer.begin(), plaintext_buffer.begin() + plaintext_len);
}

std::vector<unsigned char>
encrypt_gcm(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase)
{

    std::vector<unsigned char> encrypted_bin = encrypt_gcm_bin(data, passphrase);
    return base64_encode(encrypted_bin);
}

std::vector<unsigned char>
decrypt_gcm(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase)
{
    std::vector<unsigned char> decoded_bin = base64_decode(data);
    std::vector<unsigned char> decrypted_bin = decrypt_gcm_bin(decoded_bin, passphrase); // Removed extra data arg
    return decrypted_bin;
}
