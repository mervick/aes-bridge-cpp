#include "gtest/gtest.h"
#include "nlohmann/json.hpp"
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>

#include "aesbridge.hpp"

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string length must be even.");
    }
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), NULL, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::vector<unsigned char> stringToBytes(const std::string& str) {
    return std::vector<unsigned char>(str.begin(), str.end());
}

std::string bytesToString(const std::vector<unsigned char>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

struct TestData {
    std::vector<unsigned char> plaintext;
    std::vector<unsigned char> passphrase;
    std::string test_id;
};

// Fixture for AES bridge tests
class AesBridgeTest : public ::testing::Test {
protected:
    static nlohmann::json test_data_json;
    static bool data_loaded;

    static void SetUpTestSuite() {
        if (!data_loaded) {
            std::ifstream file("test_data.json");
            if (file.is_open()) {
                file >> test_data_json;
                data_loaded = true;
            } else {
                FAIL() << "Unable to open test_data.json. Make sure the file exists and path is correct.";
            }
        }
    }
};

nlohmann::json AesBridgeTest::test_data_json = nlohmann::json();
bool AesBridgeTest::data_loaded = false;


TEST_F(AesBridgeTest, PlaintextEncryptCbcNotEmpty) {
    ASSERT_TRUE(data_loaded) << "Test data not loaded.";
    const auto& plaintexts = test_data_json["testdata"]["plaintext"];
    for (const auto& value_json : plaintexts) {
        std::string value_str = value_json.get<std::string>();
        std::vector<unsigned char> value_bytes = stringToBytes(value_str);

        std::vector<unsigned char> encrypted = encrypt_cbc(value_bytes, value_bytes);
        ASSERT_FALSE(encrypted.empty()) << "CBC encryption result should not be empty for plaintext: " << value_str;
    }
}

TEST_F(AesBridgeTest, PlaintextEncryptGcmNotEmpty) {
    ASSERT_TRUE(data_loaded) << "Test data not loaded.";
    const auto& plaintexts = test_data_json["testdata"]["plaintext"];
    for (const auto& value_json : plaintexts) {
        std::string value_str = value_json.get<std::string>();
        std::vector<unsigned char> value_bytes = stringToBytes(value_str);

        std::vector<unsigned char> encrypted = encrypt_gcm(value_bytes, value_bytes);
        ASSERT_FALSE(encrypted.empty()) << "GCM encryption result should not be empty for plaintext: " << value_str;
    }
}

TEST_F(AesBridgeTest, PlaintextEncryptLegacyNotEmpty) {
    ASSERT_TRUE(data_loaded) << "Test data not loaded.";
    const auto& plaintexts = test_data_json["testdata"]["plaintext"];
    for (const auto& value_json : plaintexts) {
        std::string value_str = value_json.get<std::string>();
        std::vector<unsigned char> value_bytes = stringToBytes(value_str);

        std::vector<unsigned char> encrypted = encrypt_legacy(value_bytes, value_bytes);
        ASSERT_FALSE(encrypted.empty()) << "Legacy encryption result should not be empty for plaintext: " << value_str;
    }
}

TEST_F(AesBridgeTest, PlaintextEncryptDecryptCbc) {
    ASSERT_TRUE(data_loaded) << "Test data not loaded.";
    const auto& plaintexts = test_data_json["testdata"]["plaintext"];
    for (const auto& value_json : plaintexts) {
        std::string value_str = value_json.get<std::string>();
        std::vector<unsigned char> value_bytes = stringToBytes(value_str);

        std::vector<unsigned char> encrypted = encrypt_cbc(value_bytes, value_bytes);
        std::vector<unsigned char> decrypted = decrypt_cbc(encrypted, value_bytes);
        ASSERT_EQ(value_bytes, decrypted) << "CBC encryption/decryption failed for plaintext: " << value_str;
    }
}

TEST_F(AesBridgeTest, PlaintextEncryptDecryptGcm) {
    ASSERT_TRUE(data_loaded) << "Test data not loaded.";
    const auto& plaintexts = test_data_json["testdata"]["plaintext"];
    for (const auto& value_json : plaintexts) {
        std::string value_str = value_json.get<std::string>();
        std::vector<unsigned char> value_bytes = stringToBytes(value_str);

        std::vector<unsigned char> encrypted = encrypt_gcm(value_bytes, value_bytes);
        std::vector<unsigned char> decrypted = decrypt_gcm(encrypted, value_bytes);
        ASSERT_EQ(value_bytes, decrypted) << "GCM encryption/decryption failed for plaintext: " << value_str;
    }
}

TEST_F(AesBridgeTest, PlaintextEncryptDecryptLegacy) {
    ASSERT_TRUE(data_loaded) << "Test data not loaded.";
    const auto& plaintexts = test_data_json["testdata"]["plaintext"];
    for (const auto& value_json : plaintexts) {
        std::string value_str = value_json.get<std::string>();
        std::vector<unsigned char> value_bytes = stringToBytes(value_str);

        std::vector<unsigned char> encrypted = encrypt_legacy(value_bytes, value_bytes);
        std::vector<unsigned char> decrypted = decrypt_legacy(encrypted, value_bytes);
        ASSERT_EQ(value_bytes, decrypted) << "Legacy encryption/decryption failed for plaintext: " << value_str;
    }
}

TEST_F(AesBridgeTest, HexEncryptCbcNotEmpty) {
    ASSERT_TRUE(data_loaded) << "Test data not loaded.";
    const auto& hex_data_array = test_data_json["testdata"]["hex"];
    for (const auto& hex_str_json : hex_data_array) {
        std::string hex_str = hex_str_json.get<std::string>();
        std::vector<unsigned char> test_text = hexToBytes(hex_str);

        std::vector<unsigned char> encrypted = encrypt_cbc(test_text, test_text);
        ASSERT_FALSE(encrypted.empty()) << "CBC encryption result should not be empty for hex: " << hex_str;
    }
}

TEST_F(AesBridgeTest, HexEncryptGcmNotEmpty) {
    ASSERT_TRUE(data_loaded) << "Test data not loaded.";
    const auto& hex_data_array = test_data_json["testdata"]["hex"];
    for (const auto& hex_str_json : hex_data_array) {
        std::string hex_str = hex_str_json.get<std::string>();
        std::vector<unsigned char> test_text = hexToBytes(hex_str);

        std::vector<unsigned char> encrypted = encrypt_gcm(test_text, test_text);
        ASSERT_FALSE(encrypted.empty()) << "GCM encryption result should not be empty for hex: " << hex_str;
    }
}

TEST_F(AesBridgeTest, HexEncryptLegacyNotEmpty) {
    ASSERT_TRUE(data_loaded) << "Test data not loaded.";
    const auto& hex_data_array = test_data_json["testdata"]["hex"];
    for (const auto& hex_str_json : hex_data_array) {
        std::string hex_str = hex_str_json.get<std::string>();
        std::vector<unsigned char> test_text = hexToBytes(hex_str);

        std::vector<unsigned char> encrypted = encrypt_legacy(test_text, test_text);
        ASSERT_FALSE(encrypted.empty()) << "Legacy encryption result should not be empty for hex: " << hex_str;
    }
}

TEST_F(AesBridgeTest, HexEncryptDecryptCbc) {
    ASSERT_TRUE(data_loaded) << "Test data not loaded.";
    const auto& hex_data_array = test_data_json["testdata"]["hex"];
    for (const auto& hex_str_json : hex_data_array) {
        std::string hex_str = hex_str_json.get<std::string>();
        std::vector<unsigned char> test_text = hexToBytes(hex_str);

        std::vector<unsigned char> encrypted = encrypt_cbc(test_text, test_text);
        std::vector<unsigned char> decrypted = decrypt_cbc(encrypted, test_text);
        ASSERT_EQ(test_text, decrypted) << "CBC encryption/decryption failed for hex: " << hex_str;
    }
}

TEST_F(AesBridgeTest, HexEncryptDecryptGcm) {
    ASSERT_TRUE(data_loaded) << "Test data not loaded.";
    const auto& hex_data_array = test_data_json["testdata"]["hex"];
    for (const auto& hex_str_json : hex_data_array) {
        std::string hex_str = hex_str_json.get<std::string>();
        std::vector<unsigned char> test_text = hexToBytes(hex_str);

        std::vector<unsigned char> encrypted = encrypt_gcm(test_text, test_text);
        std::vector<unsigned char> decrypted = decrypt_gcm(encrypted, test_text);
        ASSERT_EQ(test_text, decrypted) << "GCM encryption/decryption failed for hex: " << hex_str;
    }
}

TEST_F(AesBridgeTest, HexEncryptDecryptLegacy) {
    ASSERT_TRUE(data_loaded) << "Test data not loaded.";
    const auto& hex_data_array = test_data_json["testdata"]["hex"];
    for (const auto& hex_str_json : hex_data_array) {
        std::string hex_str = hex_str_json.get<std::string>();
        std::vector<unsigned char> test_text = hexToBytes(hex_str);

        std::vector<unsigned char> encrypted = encrypt_legacy(test_text, test_text);
        std::vector<unsigned char> decrypted = decrypt_legacy(encrypted, test_text);
        ASSERT_EQ(test_text, decrypted) << "Legacy encryption/decryption failed for hex: " << hex_str;
    }
}


TEST_F(AesBridgeTest, DecryptGcmTests) {
    ASSERT_TRUE(data_loaded) << "Test data not loaded.";
    const auto& decrypt_cases = test_data_json["decrypt"];
    for (const auto& test_case : decrypt_cases) {
        std::string test_id = test_case.count("id") ? test_case["id"].get<std::string>() : "unknown_id";

        std::string plaintext;
        std::vector<unsigned char> plaintext_bytes;

        if (test_case.count("plaintext") && !test_case["plaintext"].is_null()) {
            plaintext = test_case["plaintext"].get<std::string>();
            plaintext_bytes = stringToBytes(plaintext);
        } else if (test_case.count("hex") && !test_case["hex"].is_null()) {
            plaintext_bytes = hexToBytes(test_case["hex"].get<std::string>());
            plaintext = bytesToString(plaintext_bytes);
        } else {
            continue;
        }

        if (!test_case.count("passphrase") || test_case["passphrase"].is_null()) {
            continue;
        }

        if (test_case.count("encrypted-gcm") && !test_case["encrypted-gcm"].is_null()) {
            std::string passphrase = test_case["passphrase"].get<std::string>();
            std::vector<unsigned char> passphrase_bytes = stringToBytes(passphrase);
            std::string encrypted_gcm = test_case["encrypted-gcm"].get<std::string>();
            std::vector<unsigned char> encrypted_gcm_bytes = stringToBytes(encrypted_gcm);

            // Test std::vector<unsigned char> decryption
            ASSERT_NO_THROW(decrypt_gcm(encrypted_gcm_bytes, passphrase_bytes)) << "Failed for test ID: " << test_id << ", std::vector<unsigned char> decryption failed";
            std::vector<unsigned char> decrypted_bytes = decrypt_gcm(encrypted_gcm_bytes, passphrase_bytes);
            ASSERT_EQ(plaintext_bytes, decrypted_bytes) << "GCM decryption failed for test ID: " << test_id;

            // Test std::string decryption
            ASSERT_NO_THROW(decrypt_gcm(encrypted_gcm, passphrase)) << "Failed for test ID: " << test_id << ", std::string decryption failed";
            std::string decrypted = decrypt_gcm(encrypted_gcm, passphrase);
            ASSERT_EQ(plaintext, decrypted) << "Failed for test ID: " << test_id << ", std::string decryption failed";
        }
    }
}

TEST_F(AesBridgeTest, DecryptCbcTests) {
    ASSERT_TRUE(data_loaded) << "Test data not loaded.";
    const auto& decrypt_cases = test_data_json["decrypt"];
    for (const auto& test_case : decrypt_cases) {
        std::string test_id = test_case.count("id") ? test_case["id"].get<std::string>() : "unknown_id";

        std::string plaintext;
        std::vector<unsigned char> plaintext_bytes;
        if (test_case.count("plaintext") && !test_case["plaintext"].is_null()) {
            plaintext = test_case["plaintext"].get<std::string>();
            plaintext_bytes = stringToBytes(plaintext);
        } else if (test_case.count("hex") && !test_case["hex"].is_null()) {
            plaintext_bytes = hexToBytes(test_case["hex"].get<std::string>());
            plaintext = bytesToString(plaintext_bytes);
        } else {
            continue;
        }

        if (!test_case.count("passphrase") || test_case["passphrase"].is_null()) {
            continue;
        }

        if (test_case.count("encrypted-cbc") && !test_case["encrypted-cbc"].is_null()) {
            std::string passphrase = test_case["passphrase"].get<std::string>();
            std::vector<unsigned char> passphrase_bytes = stringToBytes(passphrase);
            std::string encrypted_cbc = test_case["encrypted-cbc"].get<std::string>();
            std::vector<unsigned char> encrypted_cbc_bytes = stringToBytes(encrypted_cbc);

            // Test std::vector<unsigned char> decryption
            ASSERT_NO_THROW(decrypt_cbc(encrypted_cbc_bytes, passphrase_bytes)) << "Failed for test ID: " << test_id << ", std::vector<unsigned char> decryption failed";
            std::vector<unsigned char> decrypted_bytes = decrypt_cbc(encrypted_cbc_bytes, passphrase_bytes);
            ASSERT_EQ(plaintext_bytes, decrypted_bytes) << "Failed for test ID: " << test_id << ", std::vector<unsigned char> decryption failed";

            // Test std::string decryption
            ASSERT_NO_THROW(decrypt_cbc(encrypted_cbc, passphrase)) << "Failed for test ID: " << test_id << ", std::string decryption failed";
            std::string decrypted = decrypt_cbc(encrypted_cbc, passphrase);
            ASSERT_EQ(plaintext, decrypted) << "Failed for test ID: " << test_id << ", std::string decryption failed";
        }
    }
}

TEST_F(AesBridgeTest, DecryptLegacyTests) {
    ASSERT_TRUE(data_loaded) << "Test data not loaded.";
    const auto& decrypt_cases = test_data_json["decrypt"];
    for (const auto& test_case : decrypt_cases) {
        std::string test_id = test_case.count("id") ? test_case["id"].get<std::string>() : "unknown_id";

        std::string plaintext;
        std::vector<unsigned char> plaintext_bytes;

        if (test_case.count("plaintext") && !test_case["plaintext"].is_null()) {
            plaintext = test_case["plaintext"].get<std::string>();
            plaintext_bytes = stringToBytes(plaintext);
        } else if (test_case.count("hex") && !test_case["hex"].is_null()) {
            plaintext_bytes = hexToBytes(test_case["hex"].get<std::string>());
            plaintext = bytesToString(plaintext_bytes);
        } else {
            continue;
        }

        if (!test_case.count("passphrase") || test_case["passphrase"].is_null()) {
            continue;
        }

        if (test_case.count("encrypted-legacy") && !test_case["encrypted-legacy"].is_null()) {
            std::string passphrase = test_case["passphrase"].get<std::string>();
            std::vector<unsigned char> passphrase_bytes = stringToBytes(passphrase);
            std::string encrypted_legacy = test_case["encrypted-legacy"].get<std::string>();
            std::vector<unsigned char> encrypted_legacy_bytes = stringToBytes(encrypted_legacy);

            // Test std::vector<unsigned char> decryption
            ASSERT_NO_THROW(decrypt_legacy(encrypted_legacy_bytes, passphrase_bytes)) << "Failed for test ID: " << test_id << ", std::vector<unsigned char> decryption failed";
            std::vector<unsigned char> decrypted_bytes = decrypt_legacy(encrypted_legacy_bytes, passphrase_bytes);
            ASSERT_EQ(plaintext_bytes, decrypted_bytes) << "Failed for test ID: " << test_id << ", std::vector<unsigned char> decryption failed";

            // Test std::string decryption
            ASSERT_NO_THROW(decrypt_legacy(encrypted_legacy, passphrase)) << "Failed for test ID: " << test_id << ", std::string decryption failed";
            std::string decrypted = decrypt_legacy(encrypted_legacy, passphrase);
            ASSERT_EQ(plaintext, decrypted) << "Failed for test ID: " << test_id << ", std::string decryption failed";
        }
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
