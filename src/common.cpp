#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <climits>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "common.hpp"


static std::vector<unsigned char>
gen_random(size_t size)
{
    std::vector<unsigned char> buffer(size);
    if (RAND_bytes(buffer.data(), size) != 1) {
        throw std::runtime_error("Error generating random bytes with RAND_bytes.");
    }
    return buffer;
}

static uint64_t _nonce_global = 0;

std::vector<unsigned char>
generate_random(size_t size)
{
    _nonce_global++;

    if (_nonce_global == UINT64_MAX) {
        _nonce_global = 0;
    }

    std::vector<unsigned char> nonce_bytes(8);
    for (int i = 0; i < 8; ++i) {
        nonce_bytes[7 - i] = (_nonce_global >> (i * 8)) & 0xFF;
    }

    std::vector<unsigned char> data_combined;
    std::vector<unsigned char> part1 = gen_random(13);
    std::vector<unsigned char> part2 = gen_random(13);

    data_combined.insert(data_combined.end(), part1.begin(), part1.end());
    data_combined.insert(data_combined.end(), nonce_bytes.begin(), nonce_bytes.end());
    data_combined.insert(data_combined.end(), part2.begin(), part2.end());

    std::vector<unsigned char> hash_result(SHA256_DIGEST_LENGTH);
    SHA256(data_combined.data(), data_combined.size(), hash_result.data());

    // Truncate to desired size
    if (size > hash_result.size()) {
        throw std::runtime_error("Requested size for generate_random is too large.");
    }
    return std::vector<unsigned char>(hash_result.begin(), hash_result.begin() + size);
}

std::vector<unsigned char> to_bytes(const std::string& s)
{
    return std::vector<unsigned char>(s.begin(), s.end());
}

std::string to_string(const std::vector<unsigned char>& bytes)
{
    return std::string(bytes.begin(), bytes.end());
}

std::vector<unsigned char>
base64_encode(const std::vector<unsigned char>& data)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::vector<unsigned char> result(bufferPtr->data, bufferPtr->data + bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::vector<unsigned char>
base64_decode(const std::vector<unsigned char>& encoded_data)
{
    BIO *bio, *b64;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encoded_data.data(), encoded_data.size());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    std::vector<unsigned char> buffer(encoded_data.size());
    int decoded_len = BIO_read(bio, buffer.data(), buffer.size());
    if (decoded_len < 0) {
        throw std::runtime_error("Base64 decode error.");
    }
    buffer.resize(decoded_len);
    BIO_free_all(bio);
    return buffer;
}
