#include <iostream>
#include <iomanip>
#include <vector>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <cassert>
#include <string>
#include <cstring>

// Helper function: Convert a byte array to a hexadecimal string
std::string bytesToHex(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    for (auto byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

// Helper function: Perform SHA-256 hashing
std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

// Helper function: Perform RIPEMD-160 hashing
std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160(data.data(), data.size(), hash.data());
    return hash;
}

// Helper function: Perform Base58Check encoding
std::string base58Encode(const std::vector<unsigned char>& data) {
    static const char* base58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::string encoded;
    uint64_t value = 0;
    for (auto byte : data) {
        value = value * 256 + byte;
    }

    while (value > 0) {
        int mod = value % 58;
        encoded = base58Chars[mod] + encoded;
        value /= 58;
    }

    for (auto byte : data) {
        if (byte == 0x00) {
            encoded = '1' + encoded;
        } else {
            break;
        }
    }

    return encoded;
}

// Generate Bitcoin address from private key
std::string privateKeyToBitcoinAddress(const std::string& privateKeyHex) {
    // Convert private key to binary
    std::vector<unsigned char> privateKey(32);
    for (size_t i = 0; i < 32; ++i) {
        privateKey[i] = std::stoul(privateKeyHex.substr(i * 2, 2), nullptr, 16);
    }

    // Initialize secp256k1 context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privateKey.data())) {
        throw std::runtime_error("Failed to create public key");
    }

    // Serialize public key
    std::vector<unsigned char> serializedPubkey(33);
    size_t outputLen = serializedPubkey.size();
    secp256k1_ec_pubkey_serialize(ctx, serializedPubkey.data(), &outputLen, &pubkey, SECP256K1_EC_COMPRESSED);

    secp256k1_context_destroy(ctx);

    // Perform SHA-256 followed by RIPEMD-160
    std::vector<unsigned char> hash160 = ripemd160(sha256(serializedPubkey));

    // Add network byte (0x00 for mainnet)
    std::vector<unsigned char> addressData(1, 0x00);
    addressData.insert(addressData.end(), hash160.begin(), hash160.end());

    // Compute checksum
    std::vector<unsigned char> checksum = sha256(sha256(addressData));
    addressData.insert(addressData.end(), checksum.begin(), checksum.begin() + 4);

    // Encode in Base58
    return base58Encode(addressData);
}

int main() {
    std::string privateKeyHex = "0000000000000000000000000000000000000000000000000000000017e2551e";
    try {
        std::string bitcoinAddress = privateKeyToBitcoinAddress(privateKeyHex);
        std::cout << "Bitcoin Address: " << bitcoinAddress << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}
