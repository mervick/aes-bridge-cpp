#include <vector>
#include <string>
#include <stdexcept>
#include <numeric>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/md5.h>

#include "common.hpp"
#include "legacy.hpp"


const size_t BLOCK_SIZE = 16;
const size_t KEY_LEN = 32;
const size_t IV_LEN = 16;


std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
derive_key_and_iv(const std::vector<unsigned char>& password, const std::vector<unsigned char>& salt)
{
    std::vector<unsigned char> d;
    std::vector<unsigned char> d_i_digest_buffer(MD5_DIGEST_LENGTH);

    d.reserve(KEY_LEN + IV_LEN);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX.");
    }

    while (d.size() < KEY_LEN + IV_LEN) {
        if (1 != EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr)) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("EVP_DigestInit_ex failed.");
        }

        if (!d_i_digest_buffer.empty() && d.size() > 0) { // Check if it's not the first iteration
            if (1 != EVP_DigestUpdate(mdctx, d_i_digest_buffer.data(), d_i_digest_buffer.size())) {
                EVP_MD_CTX_free(mdctx);
                throw std::runtime_error("EVP_DigestUpdate failed for previous d_i.");
            }
        }

        if (1 != EVP_DigestUpdate(mdctx, password.data(), password.size())) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("EVP_DigestUpdate failed for password.");
        }

        if (1 != EVP_DigestUpdate(mdctx, salt.data(), salt.size())) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("EVP_DigestUpdate failed for salt.");
        }

        unsigned int md_len;
        if (1 != EVP_DigestFinal_ex(mdctx, d_i_digest_buffer.data(), &md_len)) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("EVP_DigestFinal_ex failed.");
        }

        d.insert(d.end(), d_i_digest_buffer.begin(), d_i_digest_buffer.end());
    }

    EVP_MD_CTX_free(mdctx);

    std::vector<unsigned char> key(d.begin(), d.begin() + KEY_LEN);
    std::vector<unsigned char> iv(d.begin() + KEY_LEN, d.begin() + KEY_LEN + IV_LEN);

    return {key, iv};
}


std::vector<unsigned char>
encrypt_legacy(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase)
{
    std::vector<unsigned char> salt = generate_random(8);

    auto [key, iv] = derive_key_and_iv(passphrase, salt);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX.");
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed.");
    }

    std::vector<unsigned char> ciphertext_buffer(data.size() + BLOCK_SIZE); // Max possible size
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

    EVP_CIPHER_CTX_free(ctx);

    ciphertext_buffer.resize(ciphertext_len);

    std::vector<unsigned char> result;
    result.reserve(8 + salt.size() + ciphertext_buffer.size());
    const unsigned char salted_magic[] = {'S', 'a', 'l', 't', 'e', 'd', '_', '_'};
    result.insert(result.end(), salted_magic, salted_magic + 8);
    result.insert(result.end(), salt.begin(), salt.end());
    result.insert(result.end(), ciphertext_buffer.begin(), ciphertext_buffer.end());

    return base64_encode(result);
}

std::vector<unsigned char>
decrypt_legacy(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase)
{
    std::vector<unsigned char> decoded_data = base64_decode(data);

    const unsigned char salted_magic[] = {'S', 'a', 'l', 't', 'e', 'd', '_', '_'};
    if (decoded_data.size() < 16 || // Must be at least "Salted__" (8) + salt (8)
        !std::equal(decoded_data.begin(), decoded_data.begin() + 8, salted_magic)) {
        return {};
    }

    std::vector<unsigned char> salt(decoded_data.begin() + 8, decoded_data.begin() + 16);
    std::vector<unsigned char> ciphertext(decoded_data.begin() + 16, decoded_data.end());
    auto [key, iv] = derive_key_and_iv(passphrase, salt);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX.");
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed.");
    }

    std::vector<unsigned char> decrypted_buffer(ciphertext.size() + BLOCK_SIZE);
    int len = 0;
    int decrypted_len = 0;

    if (1 != EVP_DecryptUpdate(ctx, decrypted_buffer.data(), &len, ciphertext.data(), ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed.");
    }
    decrypted_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, decrypted_buffer.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed (bad padding or corrupted data?).");
    }
    decrypted_len += len;

    EVP_CIPHER_CTX_free(ctx);

    decrypted_buffer.resize(decrypted_len);
    return decrypted_buffer;
}
