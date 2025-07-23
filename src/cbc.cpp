#include <vector>
#include <string>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include "common.hpp"
#include "cbc.hpp"


std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
derive_keys( const std::vector<unsigned char>& passphrase, const std::vector<unsigned char>& salt)
{
    std::vector<unsigned char> key_material(64); // 32 for AES, 32 for HMAC

    // PBKDF2 with HMAC-SHA256
    if (PKCS5_PBKDF2_HMAC(
        reinterpret_cast<const char*>(passphrase.data()), passphrase.size(),
        salt.data(), salt.size(),
        100000,           // iterations
        EVP_sha256(),     // algorithm
        key_material.size(), // key length
        key_material.data()
    ) != 1) {
        throw std::runtime_error("Key derivation failed.");
    }

    std::vector<unsigned char> aes_key(key_material.begin(), key_material.begin() + 32);
    std::vector<unsigned char> hmac_key(key_material.begin() + 32, key_material.end());

    return {aes_key, hmac_key};
}

std::vector<unsigned char>
encrypt_cbc_bin(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase)
{
    std::vector<unsigned char> salt = generate_random(16);
    std::vector<unsigned char> iv = generate_random(16);
    auto [aes_key, hmac_key] = derive_keys(passphrase, salt);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create encryption context.");
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed.");
    }

    std::vector<unsigned char> ciphertext_buffer(data.size() + 16);
    int len = 0;
    int ciphertext_len = 0;

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
    ciphertext_buffer.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);

    std::vector<unsigned char> hmac_input = iv;
    hmac_input.insert(hmac_input.end(), ciphertext_buffer.begin(), ciphertext_buffer.end());

    unsigned char tag_buffer[EVP_MAX_MD_SIZE];
    unsigned int tag_len = 0;

    if (HMAC(EVP_sha256(), hmac_key.data(), hmac_key.size(),
             hmac_input.data(), hmac_input.size(),
             tag_buffer, &tag_len) == nullptr) {
        throw std::runtime_error("HMAC calculation failed.");
    }
    std::vector<unsigned char> tag(tag_buffer, tag_buffer + tag_len);

    std::vector<unsigned char> result = salt;
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext_buffer.begin(), ciphertext_buffer.end());
    result.insert(result.end(), tag.begin(), tag.end());

    return result;
}

std::vector<unsigned char>
decrypt_cbc_bin(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase)
{
    if (data.size() < 16 + 16 + 32) {
        throw std::runtime_error("Invalid encrypted data format or too short.");
    }

    std::vector<unsigned char> salt(data.begin(), data.begin() + 16);
    std::vector<unsigned char> iv(data.begin() + 16, data.begin() + 32);
    std::vector<unsigned char> tag(data.end() - 32, data.end());
    std::vector<unsigned char> ciphertext(data.begin() + 32, data.end() - 32);

    auto [aes_key, hmac_key] = derive_keys(passphrase, salt);

    // Verify HMAC
    std::vector<unsigned char> hmac_input = iv;
    hmac_input.insert(hmac_input.end(), ciphertext.begin(), ciphertext.end());

    unsigned char expected_tag_buffer[EVP_MAX_MD_SIZE];
    unsigned int expected_tag_len = 0;

    if (HMAC(EVP_sha256(), hmac_key.data(), hmac_key.size(),
             hmac_input.data(), hmac_input.size(),
             expected_tag_buffer, &expected_tag_len) == nullptr) {
        throw std::runtime_error("HMAC verification failed (calculation error).");
    }
    std::vector<unsigned char> expected_tag(expected_tag_buffer, expected_tag_buffer + expected_tag_len);

    if (expected_tag.size() != tag.size() || CRYPTO_memcmp(expected_tag.data(), tag.data(), tag.size()) != 0) {
        throw std::runtime_error("HMAC verification failed: tags do not match.");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create decryption context.");
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed.");
    }

    std::vector<unsigned char> plaintext_buffer(ciphertext.size() + 16); // Max possible size with padding
    int len = 0;
    int plaintext_len = 0;

    if (1 != EVP_DecryptUpdate(ctx, plaintext_buffer.data(), &len, ciphertext.data(), ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed.");
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext_buffer.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed (bad padding or corrupted data).");
    }
    plaintext_len += len;
    plaintext_buffer.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_buffer;
}

std::vector<unsigned char>
encrypt_cbc(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase)
{
    std::vector<unsigned char> encrypted_bin = encrypt_cbc_bin(data, passphrase);
    return base64_encode(encrypted_bin);
}

std::vector<unsigned char>
decrypt_cbc(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase)
{
    std::vector<unsigned char> decoded_data = base64_decode(data);
    return decrypt_cbc_bin(decoded_data, passphrase);
}

// Overloaded functions to handle std::string input/output

std::string
encrypt_cbc_bin(const std::string& data, const std::string& passphrase)
{
    return to_string(encrypt_cbc_bin(to_bytes(data), to_bytes(passphrase)));
}

std::string
decrypt_cbc_bin(const std::string& data, const std::string& passphrase)
{
    return to_string(decrypt_cbc_bin(to_bytes(data), to_bytes(passphrase)));
}

std::string
encrypt_cbc(const std::string& data, const std::string& passphrase)
{
    return to_string(encrypt_cbc(to_bytes(data), to_bytes(passphrase)));
}

std::string
decrypt_cbc(const std::string& data, const std::string& passphrase)
{
    return to_string(decrypt_cbc(to_bytes(data), to_bytes(passphrase)));
}
