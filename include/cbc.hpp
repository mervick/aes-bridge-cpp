#ifndef AESBRIDGE_CBC_HPP
#define AESBRIDGE_CBC_HPP

#include <vector>
#include <string>
#include <utility>
#include <cstdint>


/**
 * @brief Derives AES and HMAC keys from a passphrase and salt using PBKDF2HMAC.
 * This function is typically internal but exposed for potential advanced use cases.
 * @param passphrase The passphrase as a vector of unsigned characters.
 * @param salt The salt as a vector of unsigned characters.
 * @return A pair containing the AES key (first) and HMAC key (second).
 * @throws std::runtime_error if key derivation fails.
 */
std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
derive_keys( const std::vector<unsigned char>& passphrase, const std::vector<unsigned char>& salt);

/**
 * @brief Encrypts data using AES-256 CBC mode with PKCS7 padding and HMAC-SHA256 authentication.
 *
 * @param data Data to encrypt.
 * @param passphrase Encryption passphrase.
 * @return Encrypted data in format: salt (16 bytes) + IV (16 bytes) +
 * ciphertext (variable length) + HMAC tag (32 bytes).
 * @throws std::runtime_error on encryption or HMAC failure.
 */
std::vector<unsigned char>
encrypt_cbc_bin(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase);

/**
 * @brief Decrypts data encrypted with encrypt_cbc_bin() function.
 *
 * @param data Encrypted data in format: salt (16) + IV (16) + ciphertext (N) + HMAC (32).
 * @param passphrase Passphrase used for encryption.
 * @return Decrypted plaintext data.
 * @throws std::runtime_error on decryption, HMAC verification, or data format issues.
 */
std::vector<unsigned char>
decrypt_cbc_bin(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase);

/**
 * @brief Encrypts data and returns result as base64 encoded bytes.
 *
 * @param data Data to encrypt.
 * @param passphrase Encryption passphrase.
 * @return Base64 encoded encrypted data.
 * @throws std::runtime_error on encryption or encoding failure.
 */
std::vector<unsigned char>
encrypt_cbc(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase);

/**
 * @brief Decrypts base64 encoded data encrypted with encrypt_cbc().
 *
 * @param data Base64 encoded encrypted data as a std::string.
 * @param passphrase Encryption passphrase.
 * @return Decrypted plaintext data.
 * @throws std::runtime_error on decoding, decryption, or verification failure.
 */
std::vector<unsigned char>
decrypt_cbc(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase);


#endif // AESBRIDGE_CBC_HPP
