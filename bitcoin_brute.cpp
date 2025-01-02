#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

// Function to convert bytes to a hex string (optional, for debugging)
std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    for (unsigned char byte : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return ss.str();
}

// Perform SHA-256
std::vector<unsigned char> sha256(const std::vector<unsigned char>& input) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    EVP_Digest(input.data(), input.size(), hash.data(), nullptr, EVP_sha256(), nullptr);
    return hash;
}

// Perform RIPEMD-160
std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& input) {
    std::vector<unsigned char> hash(RIPEMD160_DIGEST_LENGTH);
    EVP_Digest(input.data(), input.size(), hash.data(), nullptr, EVP_ripemd160(), nullptr);
    return hash;
}

// Encode a byte array in Base58
std::string encodeBase58(const std::vector<unsigned char>& input) {
    const char* base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::vector<unsigned char> data(input.begin(), input.end());

    // Count leading zeroes
    int zeroCount = 0;
    while (zeroCount < data.size() && data[zeroCount] == 0) {
        ++zeroCount;
    }

    // Convert the binary data to Base58
    std::vector<unsigned char> temp(data.size() * 2);
    int j = temp.size();
    for (size_t i = zeroCount; i < data.size(); ++i) {
        int carry = data[i];
        int k = temp.size() - 1;
        while (carry || k >= j) {
            carry += 256 * temp[k];
            temp[k] = carry % 58;
            carry /= 58;
            --k;
        }
        j = k + 1;
    }

    // Skip leading zeroes in temp
    while (j < temp.size() && temp[j] == 0) {
        ++j;
    }

    // Construct the final Base58 string
    std::string result;
    result.reserve(zeroCount + (temp.size() - j));
    result.assign(zeroCount, '1'); // Leading zeroes in Base58 are '1'
    for (size_t k = j; k < temp.size(); ++k) {
        result += base58Alphabet[temp[k]];
    }

    return result;
}

// Generate a Bitcoin address from a private key
std::string deriveBitcoinAddress(const std::vector<unsigned char>& privateKey) {
    // Create the key context and set curve parameters
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize EC key context");
    }

    // Generate the key pair
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate EC key");
    }
    EVP_PKEY_CTX_free(ctx);

    // Get the public key in uncompressed format
    size_t pubKeyLen = 0;
    EVP_PKEY_get_raw_public_key(pkey, nullptr, &pubKeyLen);
    std::vector<unsigned char> pubKey(pubKeyLen);
    if (EVP_PKEY_get_raw_public_key(pkey, pubKey.data(), &pubKeyLen) <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to get public key");
    }

    // Perform SHA-256 and RIPEMD-160
    std::vector<unsigned char> pubKeyHash = ripemd160(sha256(pubKey));

    // Add version byte (0x00 for Bitcoin mainnet)
    std::vector<unsigned char> addressBytes = {0x00};
    addressBytes.insert(addressBytes.end(), pubKeyHash.begin(), pubKeyHash.end());

    // Compute checksum
    std::vector<unsigned char> checksum = sha256(sha256(addressBytes));
    addressBytes.insert(addressBytes.end(), checksum.begin(), checksum.begin() + 4);

    // Convert to Base58
    std::string bitcoinAddress = encodeBase58(addressBytes);

    // Clean up
    EVP_PKEY_free(pkey);
    return bitcoinAddress;
}

int main() {
    // Example private key (in reality, private keys are 32 bytes)
    std::vector<unsigned char> privateKey = {0x28, 0x32, 0xED, 0x74, 0xF2, 0xB5, 0xE3, 0x5E, 0xEE, 0x34, 0x9B, 0x84, 0xB6, 0x43, 0x1A, 0x6C, 0x4E, 0xF1};

    try {
        std::string bitcoinAddress = deriveBitcoinAddress(privateKey);
        std::cout << "Bitcoin Address: " << bitcoinAddress << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
