#ifndef AESBRIDGE_GCM_HPP
#define AESBRIDGE_GCM_HPP

#include <vector>
#include <string>
#include <cstdint>

/**
 * @brief Derives a cryptographic key from a passphrase and salt using PBKDF2-HMAC-SHA256.
 *
 * @param passphrase The passphrase as a vector of unsigned characters.
 * @param salt The salt as a vector of unsigned characters.
 * @return A derived key as a vector of unsigned characters.
 * @throws std::runtime_error if key derivation fails.
 */
// std::vector<unsigned char>
// derive_key(const std::vector<unsigned char>& passphrase, const std::vector<unsigned char>& salt);

/**
 * @brief Encrypts data using AES-256-GCM mode.
 *
 * @param data Data to encrypt.
 * @param passphrase Encryption passphrase.
 * @return Encrypted data in format: salt (16 bytes) + nonce (12 bytes) + ciphertext (variable length) + tag (16 bytes).
 * @throws std::runtime_error on encryption failure.
 */
std::vector<unsigned char>
encrypt_gcm_bin(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase);

/**
 * @brief Encrypts data using AES-256-GCM mode.
 *
 * @param data Data to encrypt.
 * @param passphrase Encryption passphrase.
 * @return Encrypted data in format: salt (16 bytes) + nonce (12 bytes) + ciphertext (variable length) + tag (16 bytes).
 * @throws std::runtime_error on encryption failure.
 */
std::string
encrypt_gcm_bin(const std::string& data, const std::string& passphrase);

/**
 * @brief Decrypts data encrypted with encrypt_gcm_bin() function.
 *
 * @param data Encrypted data in format: salt (16 bytes) + nonce (12 bytes) + ciphertext (variable length) + tag (16 bytes).
 * @param passphrase Passphrase used for encryption.
 * @return Decrypted plaintext data.
 * @throws std::runtime_error on decryption or verification failure.
 */
std::vector<unsigned char>
decrypt_gcm_bin(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase);

/**
 * @brief Decrypts data encrypted with encrypt_gcm_bin() function.
 *
 * @param data Encrypted data in format: salt (16 bytes) + nonce (12 bytes) + ciphertext (variable length) + tag (16 bytes).
 * @param passphrase Passphrase used for encryption.
 * @return Decrypted plaintext data.
 * @throws std::runtime_error on decryption or verification failure.
 */
std::string
decrypt_gcm_bin(const std::string& data, const std::string& passphrase);

/**
 * @brief Encrypts data using AES-256-GCM mode and returns the encrypted data as a base64 encoded string.
 *
 * @param data Data to encrypt.
 * @param passphrase Encryption passphrase.
 * @return Base64 encoded encrypted data.
 * @throws std::runtime_error on encryption failure.
 */
std::vector<unsigned char>
encrypt_gcm(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase);

/**
 * @brief Encrypts data using AES-256-GCM mode and returns the encrypted data as a base64 encoded string.
 *
 * @param data Data to encrypt.
 * @param passphrase Encryption passphrase.
 * @return Base64 encoded encrypted data.
 * @throws std::runtime_error on encryption failure.
 */
std::string
encrypt_gcm(const std::string& data, const std::string& passphrase);

/**
 * @brief Decrypts base64 encoded data encrypted with encrypt_gcm() function.
 *
 * @param data Base64 encoded encrypted data.
 * @param passphrase Passphrase used for encryption.
 * @return Decrypted plaintext data.
 * @throws std::runtime_error on decryption or verification failure.
 */
std::vector<unsigned char>
decrypt_gcm(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase);


/**
 * @brief Decrypts base64 encoded data encrypted with encrypt_gcm() function.
 *
 * @param data Base64 encoded encrypted data.
 * @param passphrase Passphrase used for encryption.
 * @return Decrypted plaintext data.
 * @throws std::runtime_error on decryption or verification failure.
 */
std::string
decrypt_gcm(const std::string& data, const std::string& passphrase);


#endif // AESBRIDGE_GCM_HPP
