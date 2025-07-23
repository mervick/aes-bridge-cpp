#ifndef AESBRIDGE_LEGACY_HPP
#define AESBRIDGE_LEGACY_HPP

#include <vector>
#include <string>
#include <utility>


/**
 * @brief Derives a cryptographic key and initialization vector (IV) from a password and salt using an MD5-based algorithm
 *
 * This function uses an MD5-based algorithm that is compatible with OpenSSL's legacy EVP_BytesToKey function.
 *
 * @param password The password used for key derivation, represented as a vector of unsigned characters.
 * @param salt The salt used during the derivation process, represented as a vector of unsigned characters.
 * @return A pair containing the derived key (first) and IV (second) as vectors of unsigned characters.
 * @throws std::runtime_error if the derivation process encounters an error.
 */
std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
derive_key_and_iv(const std::vector<unsigned char>& password, const std::vector<unsigned char>& salt);

/**
 * @brief Encrypts plaintext data using AES-256-CBC with a passphrase,
 * producing an OpenSSL-compatible "Salted__" format, then Base64-encodes the result.
 * @param data: The plaintext data to encrypt.
 * @param passphrase: The passphrase for key derivation.
 * @return: Encrypted data, Base64-encoded.
 * @throws std::runtime_error on cryptographic operation failure.
 */
std::vector<unsigned char>
encrypt_legacy(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase);

/**
 * @brief Decrypts Base64-encoded AES-256-CBC data using a passphrase,
 * expecting the OpenSSL-compatible "Salted__" format.
 *
 * @param data: The encrypted data, Base64-encoded.
 * @param passphrase: The passphrase for key derivation.
 * @return: Decrypted plaintext data. Returns an empty vector if "Salted__" header is missing.
 * @throws std::runtime_error on cryptographic operation failure (e.g., bad padding, invalid input).
 */
std::vector<unsigned char>
decrypt_legacy(const std::vector<unsigned char>& data, const std::vector<unsigned char>& passphrase);


#endif // AESBRIDGE_LEGACY_HPP
