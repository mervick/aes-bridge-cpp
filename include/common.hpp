#ifndef AESBRIDGE_COMMON_HPP
#define AESBRIDGE_COMMON_HPP

#include <vector>
#include <string>
#include <cstdint>

/**
 * @brief Convert a string to a vector of bytes.
 *
 * @param s A string to convert to a vector of bytes.
 * @return A vector of bytes containing the characters of the string.
 */
std::vector<unsigned char>
to_bytes(const std::string& s);

/**
 * @brief Convert a vector of bytes to a string.
 *
 * @param bytes A vector of bytes to convert to a string.
 * @return A string containing the bytes from the vector.
 */
std::string
to_string(const std::vector<unsigned char>& bytes);

/**
 * @brief Generate a vector of size bytes, filled with cryptographically secure random values.
 *
 * @param size The number of bytes to generate.
 * @return A vector of size bytes, filled with random values.
 * @throws std::runtime_error If error occurs generating random bytes.
 */
std::vector<unsigned char>
generate_random(size_t size);

/**
 * @brief Encode the given data as a vector of base64 bytes.
 *
 * @param data Data to encode.
 * @return A vector of base64 bytes representing the encoded data.
 */
std::vector<unsigned char>
base64_encode(const std::vector<unsigned char>& data);

/**
 * @brief Decode the given base64 encoded data as a vector of bytes.
 *
 * @param encoded_string A vector of base64 bytes to decode.
 * @return A vector of bytes representing the decoded data.
 * @throws std::runtime_error If error occurs decoding the data.
 */
std::vector<unsigned char>
base64_decode(const std::vector<unsigned char>& encoded_string);


#endif // AESBRIDGE_COMMON_HPP
