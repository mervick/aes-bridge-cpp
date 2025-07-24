#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <random>

#include "common.hpp"
#include "aesbridge.hpp"

void print_usage(const std::string& program_name) {
    std::cerr << "Usage: " << program_name << " <action> --mode <mode> --data <data> --passphrase <passphrase> [--b64]\n"
              << "  <action>: encrypt | decrypt\n"
              << "  --mode: cbc | gcm | legacy\n"
              << "  --data: Data to encrypt (UTF-8 string) or decrypt (base64 string).\n"
              << "  --passphrase: Passphrase for key derivation.\n"
              << "  --b64: Accept base64 encoded input and returns base64 encoded output.\n";
}

int main(int argc, char* argv[]) {
    // Parse command line arguments
    std::map<std::string, std::string> args_map;
    bool b64_flag = false;
    std::string action;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "encrypt" || arg == "decrypt") {
            if (!action.empty()) {
                std::cerr << "Error: Only one action (encrypt/decrypt) can be specified.\n";
                print_usage(argv[0]);
                return 1;
            }
            action = arg;
        } else if (arg == "--mode" && i + 1 < argc) {
            args_map["mode"] = argv[++i];
        } else if (arg == "--data" && i + 1 < argc) {
            args_map["data"] = argv[++i];
        } else if (arg == "--passphrase" && i + 1 < argc) {
            args_map["passphrase"] = argv[++i];
        } else if (arg == "--b64") {
            b64_flag = true;
        } else {
            std::cerr << "Error: Unknown argument or missing value for " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // Validate required arguments
    if (action.empty() || args_map.find("mode") == args_map.end() ||
        args_map.find("data") == args_map.end() || args_map.find("passphrase") == args_map.end()) {
        print_usage(argv[0]);
        return 1;
    }

    const std::string& mode = args_map["mode"];
    const std::string& data_str = args_map["data"];
    const std::string& passphrase = args_map["passphrase"];

    // Validate mode
    if (mode != "cbc" && mode != "gcm" && mode != "legacy") {
        std::cerr << "Error: Invalid mode. Choose from 'cbc', 'gcm', or 'legacy'.\n";
        print_usage(argv[0]);
        return 1;
    }

    try {
        std::string result;
        std::string processed_data = data_str;

        if (action == "encrypt") {
            if (b64_flag) {
                // If --b64 is present for encryption, input data is already base64 encoded
                // so we decode it before passing to encryption function.
                std::vector<unsigned char> decoded_input = base64_decode(to_bytes(data_str));
                processed_data = std::string(decoded_input.begin(), decoded_input.end());
            }

            if (mode == "cbc") {
                result = encrypt_cbc(processed_data, passphrase);
            } else if (mode == "gcm") {
                result = encrypt_gcm(processed_data, passphrase);
            } else if (mode == "legacy") {
                result = encrypt_legacy(processed_data, passphrase);
            }
        } else { // action == "decrypt"
            // For decryption, input data is always treated as base64 encoded by the CLI.
            // The decryption functions will internally base64 decode if necessary,
            // and the output will be raw unless --b64 is specified for output.
            if (mode == "cbc") {
                result = decrypt_cbc(processed_data, passphrase);
            } else if (mode == "gcm") {
                result = decrypt_gcm(processed_data, passphrase);
            } else if (mode == "legacy") {
                result = decrypt_legacy(processed_data, passphrase);
            }

            if (b64_flag) {
                // If --b64 is present for decryption, output should be base64 encoded.
                // std::vector<unsigned char> raw_decrypted(result.begin(), result.end());
                result = to_string(base64_encode(to_bytes(result)));
            }
        }
        std::cout << result << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "An unexpected error occurred." << std::endl;
        return 1;
    }

    return 0;
}
