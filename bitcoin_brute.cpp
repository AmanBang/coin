#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

// Function to convert bytes to a hex string
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

// Generate a Bitcoin address from a private key
std::string deriveBitcoinAddress(const std::vector<unsigned char>& privateKey) {
    // Create an EC key using EVP
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1);

    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    // Generate the public key
    size_t pubKeyLen = 65;
    std::vector<unsigned char> pubKey(pubKeyLen);
    EVP_PKEY_get_raw_public_key(pkey, pubKey.data(), &pubKeyLen);

    // Perform SHA-256 and RIPEMD-160
    std::vector<unsigned char> pubKeyHash = ripemd160(sha256(pubKey));

    // Add version byte (0x00 for Bitcoin mainnet)
    std::vector<unsigned char> addressBytes = {0x00};
    addressBytes.insert(addressBytes.end(), pubKeyHash.begin(), pubKeyHash.end());

    // Perform checksum
    std::vector<unsigned char> checksum = sha256(sha256(addressBytes));
    addressBytes.insert(addressBytes.end(), checksum.begin(), checksum.begin() + 4);

    // Convert to Base58 (omitted for brevity)
    std::string bitcoinAddress = bytesToHex(addressBytes);

    // Clean up
    EVP_PKEY_free(pkey);
    return bitcoinAddress;
}

// Brute force through the keyspace
void bruteForce(const std::vector<unsigned char>& startKey, const std::vector<unsigned char>& endKey, const std::string& targetAddress) {
    std::vector<unsigned char> currentKey = startKey;

    // Limit the first character to numbers (0–9)
    for (unsigned char firstChar = 0x30; firstChar <= 0x39; ++firstChar) {  // ASCII '0' to '9'
        currentKey[0] = firstChar;

        while (currentKey <= endKey) {
            std::string address = deriveBitcoinAddress(currentKey);
            if (address == targetAddress) {
                std::cout << "Private key found: " << bytesToHex(currentKey) << std::endl;
                return;
            }

            // Increment private key
            for (int i = currentKey.size() - 1; i > 0; --i) {
                if (++currentKey[i] != 0) break;
            }
        }
    }

    std::cout << ".";
}

int main() {
    // Define the starting and ending keys (replace with the actual range)
    std::vector<unsigned char> startKey = {0x28, 0x32, 0xed, 0x74, 0xf2, 0xb5, 0xe3, 0x5e, 0xee};
    std::vector<unsigned char> endKey = {0x34, 0x9b, 0x84, 0xb6, 0x43, 0x1a, 0x6c, 0x4e, 0xf1};

    // Target Bitcoin address (replace with the actual challenge address)
    std::string targetAddress = "1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9";

    // Start brute force
    bruteForce(startKey, endKey, targetAddress);

    return 0;
}
