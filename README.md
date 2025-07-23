# AesBridge CPP

![CI Status](https://github.com/mervick/aes-bridge-python/actions/workflows/linux-tests.yml/badge.svg)
![CI Status](https://github.com/mervick/aes-bridge-python/actions/workflows/mac-tests.yml/badge.svg)

**AesBridge** is a modern, secure, and cross-language **AES** encryption library. It offers a unified interface for encrypting and decrypting data across multiple programming languages. Supports **GCM**, **CBC**, and **legacy AES Everywhere** modes.

## Features

  - 🔐 AES-256 encryption in GCM (recommended) and CBC modes.
  - 🌍 Unified cross-language design.
  - 📦 Compact binary format or base64 output.
  - ✅ HMAC Integrity: CBC mode includes HMAC verification.
  - 🔄 Backward Compatible: Supports legacy AES Everywhere format.


### Installation

Assuming you're using CMake for your build system, add this project as a Git submodule and include it in your CMake project:

```cmake
# CMakeLists.txt
add_subdirectory(path/to/aes-bridge-cpp)
target_link_libraries(your_project_name PRIVATE aes-bridge)
```

### Usage

```cpp
#include <string>
#include <vector>
#include <iostream>

#include <aesbridge.h>

int main() {
    std::string message = "My secret message";
    std::string passphrase = "MyStrongPass";

    // Encrypt and decrypt using GCM mode (recommended)
    std::string gcm_ciphertext = encrypt_gcm(message, passphrase);
    std::string gcm_decrypted = decrypt_gcm(gcm_ciphertext, passphrase);

    std::cout << "Decrypted: " << decrypted << std::endl;

    // Example with CBC mode
    std::string cbc_ciphertext = encrypt_cbc(message, passphrase);
    std::string cbc_decrypted = decrypt_cbc(cbc_ciphertext, passphrase);

    return 0;
}
```


## API Reference

AesBridge functions support both `std::string` and `std::vector<unsigned char>` for input and output. The input and output types must match — if you pass in a string, you'll receive a string in return; if you pass in a byte vector, you'll get a byte vector back.

### GCM Mode (Recommended)

#### `encrypt_gcm(data, passphrase)`

Encrypts data using AES-256-GCM mode and returns the encrypted data as a base64 encoded string.

- **Parameters:**
    - `data`: `std::string` or `std::vector<unsigned char>` – Data to encrypt.
    - `passphrase`: `std::string` or `std::vector<unsigned char>` – Encryption passphrase.
- **Returns:** `std::string` or `std::vector<unsigned char>` - Base64 encoded encrypted data in the same data type as input


#### `decrypt_gcm(data, passphrase)`

Decrypts base64 encoded data encrypted with `encrypt_gcm()`.

- **Parameters:**
    - `data`: `std::string` or `std::vector<unsigned char>` – Base64 encoded encrypted data.
    - `passphrase`: `std::string` or `std::vector<unsigned char>` – Passphrase used for encryption.
- **Returns:** `std::string` or `std::vector<unsigned char>` - Plaintext in the same data type as input


#### `encrypt_gcm_bin(data, passphrase)`

Encrypts data using AES-256-GCM and returns raw binary output in the format:
`salt (16 bytes) + nonce (12 bytes) + ciphertext + tag (16 bytes)`

- **Parameters:**
    - `data`: `std::string` or `std::vector<unsigned char>` – Data to encrypt.
    - `passphrase`: `std::string` or `std::vector<unsigned char>` – Encryption passphrase.
- **Returns:** `std::string` or `std::vector<unsigned char>` - Encrypted data in the same data type as input


#### `decrypt_gcm_bin(data, passphrase)`

Decrypts binary data from `encrypt_gcm_bin()` using the given passphrase.

- **Parameters:**
    - `data`: `std::string` or `std::vector<unsigned char>` – Encrypted data.
    - `passphrase`: `std::string` or `std::vector<unsigned char>` – Passphrase used for encryption.
- **Returns:** `std::string` or `std::vector<unsigned char>` - Plaintext in the same data type as input


### CBC Mode

#### `encrypt_cbc(data, passphrase)`

Encrypts data using **AES-256-CBC** with PKCS7 padding and HMAC-SHA256 authentication.
Returns the encrypted data as a base64 encoded string.

- **Parameters:**
    - `data`: `std::string` or `std::vector<unsigned char>` – Data to encrypt.
    - `passphrase`: `std::string` or `std::vector<unsigned char>` – Encryption passphrase.
- **Returns:** `std::string` or `std::vector<unsigned char>` - Base64 encoded encrypted data in the same data type as input


#### `decrypt_cbc(data, passphrase)`

Decrypts and verifies data previously encrypted with `encrypt_cbc()`.

- **Parameters:**
    - `data`: `std::string` or `std::vector<unsigned char>` – Base64 encoded encrypted data.
    - `passphrase`: `std::string` or `std::vector<unsigned char>` – Passphrase used for encryption.
- **Returns:** `std::string` or `std::vector<unsigned char>` - Plaintext in the same data type as input


#### `encrypt_cbc_bin(data, passphrase)`

Encrypts data using AES-256-CBC; returns raw binary of format:
`salt (16 bytes) + IV (16 bytes) + ciphertext + HMAC (32 bytes)`

- **Parameters:**
    - `data`: `std::string` or `std::vector<unsigned char>` – Data to encrypt.
    - `passphrase`: `std::string` or `std::vector<unsigned char>` – Encryption passphrase.
- **Returns:** `std::string` or `std::vector<unsigned char>` - Encrypted data in the same data type as input


#### `decrypt_cbc_bin(data, passphrase)`

Decrypts and authenticates binary output from `encrypt_cbc_bin()`.

- **Parameters:**
    - `data`: `std::string` or `std::vector<unsigned char>` – Encrypted data.
    - `passphrase`: `std::string` or `std::vector<unsigned char>` – Passphrase used for encryption.
- **Returns:** `std::string` or `std::vector<unsigned char>` - Plaintext in the same data type as input


### Legacy Compatibility

> ⚠️ These functions are maintained solely for **backward compatibility** with older systems. While they remain fully compatible with the legacy **AES Everywhere** implementation, their use is strongly discouraged in new applications due to potential security limitations compared to GCM or CBC with HMAC.


#### `encrypt_legacy(data, passphrase)`

Encrypts plaintext using AES-256-CBC in OpenSSL-compatible `"Salted__"` format.
Returns Base64 (`std::string`) or binary (`std::vector<unsigned char>`) depending on input type.

- **Parameters:**
    - `data`: `std::string` or `std::vector<unsigned char>` – Data to encrypt.
    - `passphrase`: `std::string` or `std::vector<unsigned char>` – Encryption passphrase.
- **Returns:** `std::string` or `std::vector<unsigned char>` - Base64 encoded encrypted data in the same data type as input



#### `decrypt_legacy(data, passphrase)`

Decrypts data from `encrypt_legacy()`, expecting OpenSSL `"Salted__"` format.

- **Parameters:**
    - `data`: `std::string` or `std::vector<unsigned char>` – Base64 encoded encrypted data.
    - `passphrase`: `std::string` or `std::vector<unsigned char>` – Passphrase used for encryption.
- **Returns:** `std::string` or `std::vector<unsigned char>` - Plaintext in the same data type as input


