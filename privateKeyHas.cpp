#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>
#include <openssl/evp.h>
#include <algorithm>

// Function to convert hex string to bytes
std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(EVP_MAX_MD_SIZE);
    unsigned int hashLen;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, &data[0], data.size());
    EVP_DigestFinal_ex(ctx, &hash[0], &hashLen);
    EVP_MD_CTX_free(ctx);

    hash.resize(hashLen);
    return hash;
}

std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(EVP_MAX_MD_SIZE);
    unsigned int hashLen;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL);
    EVP_DigestUpdate(ctx, &data[0], data.size());
    EVP_DigestFinal_ex(ctx, &hash[0], &hashLen);
    EVP_MD_CTX_free(ctx);

    hash.resize(hashLen);
    return hash;
}

std::string base58Encode(const std::vector<unsigned char>& data) {
    const char* base58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::vector<unsigned char> digits((data.size() * 138 / 100) + 1);
    size_t digitslen = 1;
    for (size_t i = 0; i < data.size(); i++) {
        unsigned int carry = static_cast<unsigned int>(data[i]);
        for (size_t j = 0; j < digitslen; j++) {
            carry += static_cast<unsigned int>(digits[j]) << 8;
            digits[j] = static_cast<unsigned char>(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            digits[digitslen++] = static_cast<unsigned char>(carry % 58);
            carry /= 58;
        }
    }
    std::string result;
    for (size_t i = 0; i < (data.size() - 1) && data[i] == 0; i++)
        result.push_back('1');
    for (size_t i = 0; i < digitslen; i++)
        result.push_back(base58chars[digits[digitslen - 1 - i]]);
    return result;
}


std::string privateKeyToBitcoinAddress(const std::string& privateKeyHex, bool compressed) {
    std::vector<unsigned char> privateKeyBytes = hexToBytes(privateKeyHex);

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;

    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, &privateKeyBytes[0])) {
        std::cerr << "Failed to create public key" << std::endl;
        secp256k1_context_destroy(ctx);
        return "";
    }

    std::vector<unsigned char> publicKeyBytes(compressed ? 33 : 65);
    size_t publicKeyLen = compressed ? 33 : 65;
    secp256k1_ec_pubkey_serialize(ctx, &publicKeyBytes[0], &publicKeyLen, &pubkey,
                                  compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

    std::vector<unsigned char> publicKeyHash = ripemd160(sha256(publicKeyBytes));

    std::vector<unsigned char> addressPayload;
    addressPayload.push_back(0x00); // Mainnet network byte
    addressPayload.insert(addressPayload.end(), publicKeyHash.begin(), publicKeyHash.end());

    std::vector<unsigned char> checksum = sha256(sha256(addressPayload));
    addressPayload.insert(addressPayload.end(), checksum.begin(), checksum.begin() + 4);

    std::string bitcoinAddress = base58Encode(addressPayload);

    secp256k1_context_destroy(ctx);
    return bitcoinAddress;
}
int main() {
    std::string privateKeyHex = "00000000000000000000000000000000000000000000000000022bd43c2e9354";
    
    std::string compressedAddress = privateKeyToBitcoinAddress(privateKeyHex, true);
    std::string uncompressedAddress = privateKeyToBitcoinAddress(privateKeyHex, false);
    
    std::cout << "Compressed Bitcoin Address: " << compressedAddress << std::endl;
    std::cout << "Uncompressed Bitcoin Address: " << uncompressedAddress << std::endl;
    
    return 0;
}