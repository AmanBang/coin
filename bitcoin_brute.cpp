#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

// Function to convert bytes to hex string
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
    SHA256(input.data(), input.size(), hash.data());
    return hash;
}

// Perform RIPEMD-160
std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& input) {
    std::vector<unsigned char> hash(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160(input.data(), input.size(), hash.data());
    return hash;
}

// Derive Bitcoin address from private key
std::string deriveBitcoinAddress(const std::vector<unsigned char>& privateKey) {
    // Create an EC key from the private key
    EC_KEY* ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM* privKeyBN = BN_bin2bn(privateKey.data(), privateKey.size(), nullptr);
    EC_KEY_set_private_key(ecKey, privKeyBN);

    // Generate the public key
    const EC_POINT* pubKey = EC_KEY_get0_public_key(ecKey);
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    std::vector<unsigned char> pubKeyBytes(65);
    EC_POINT_point2oct(group, pubKey, POINT_CONVERSION_UNCOMPRESSED, pubKeyBytes.data(), pubKeyBytes.size(), nullptr);

    // Perform SHA-256 and RIPEMD-160
    std::vector<unsigned char> pubKeyHash = ripemd160(sha256(pubKeyBytes));

    // Add version byte (0x00 for Bitcoin mainnet)
    std::vector<unsigned char> addressBytes = {0x00};
    addressBytes.insert(addressBytes.end(), pubKeyHash.begin(), pubKeyHash.end());

    // Perform checksum
    std::vector<unsigned char> checksum = sha256(sha256(addressBytes));
    addressBytes.insert(addressBytes.end(), checksum.begin(), checksum.begin() + 4);

    // Convert to Base58 (omitted for brevity)
    std::string bitcoinAddress = bytesToHex(addressBytes);

    // Clean up
    EC_KEY_free(ecKey);
    BN_free(privKeyBN);
    EC_GROUP_free(group);

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
