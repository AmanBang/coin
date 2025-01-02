#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <thread>
#include <atomic>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

// Base58 character set
static const char* base58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Function declarations
std::string base58Encode(const std::vector<unsigned char>& input);
std::string bytesToHex(const std::vector<unsigned char>& bytes);
std::vector<unsigned char> sha256(const std::vector<unsigned char>& input);
std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& input);
std::string deriveBitcoinAddress(const std::vector<unsigned char>& privateKey, bool compressed);

std::atomic<bool> found(false);
std::vector<unsigned char> foundKey;

void incrementKey(std::vector<unsigned char>& key) {
    for (int i = key.size() - 1; i >= 0; --i) {
        if (++key[i] != 0) break;
    }
}

std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

std::vector<unsigned char> sha256(const std::vector<unsigned char>& input) {
    std::vector<unsigned char> hash(EVP_MAX_MD_SIZE);
    unsigned int hash_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input.data(), input.size());
    EVP_DigestFinal_ex(mdctx, hash.data(), &hash_len);
    EVP_MD_CTX_free(mdctx);
    hash.resize(hash_len);
    return hash;
}

std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& input) {
    std::vector<unsigned char> hash(EVP_MAX_MD_SIZE);
    unsigned int hash_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_ripemd160();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input.data(), input.size());
    EVP_DigestFinal_ex(mdctx, hash.data(), &hash_len);
    EVP_MD_CTX_free(mdctx);
    hash.resize(hash_len);
    return hash;
}


std::string base58Encode(const std::vector<unsigned char>& input) {
    BIGNUM *bn = BN_new();
    BN_bin2bn(input.data(), input.size(), bn);

    std::string result;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *dv = BN_new();
    BIGNUM *rem = BN_new();
    BIGNUM *base = BN_new();
    BN_set_word(base, 58);

    while (BN_is_zero(bn) == 0) {
        BN_div(dv, rem, bn, base, ctx);
        BN_copy(bn, dv);
        result.push_back(base58chars[BN_get_word(rem)]);
    }

    // Add leading '1's for zero bytes in input
    for (size_t i = 0; i < input.size() && input[i] == 0; i++) {
        result.push_back('1');
    }

    std::reverse(result.begin(), result.end());

    BN_free(bn);
    BN_CTX_free(ctx);
    BN_free(dv);
    BN_free(rem);
    BN_free(base);

    return result;
}

void bruteForceThread(const std::vector<unsigned char>& startKey, const std::vector<unsigned char>& endKey, const std::string& targetAddress, int threadId, int totalThreads) {
    std::vector<unsigned char> currentKey = startKey;
    for (int i = 0; i < threadId; ++i) {
        incrementKey(currentKey);
    }

    while (currentKey <= endKey && !found) {
        std::string addressUncompressed = deriveBitcoinAddress(currentKey, false);
        std::string addressCompressed = deriveBitcoinAddress(currentKey, true);

        if (addressUncompressed == targetAddress || addressCompressed == targetAddress) {
            found = true;
            foundKey = currentKey;
            std::cout << "Thread " << threadId << " found the key!" << std::endl;
            return;
        }

        for (int i = 0; i < totalThreads; ++i) {
            incrementKey(currentKey);
        }

        if (threadId == 0 && currentKey[0] % 16 == 0) {
            std::cout << "Current progress: 0x" << bytesToHex(currentKey) << std::endl;
        }
    }
}

int main() {
    std::vector<unsigned char> startKey(32, 0);
    startKey[31] = 1;  // Start from 1

    std::vector<unsigned char> endKey(32, 0);
    endKey[31] = 255;  // End at 255 (adjust as needed)

    std::string targetAddress = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

    int numThreads = std::thread::hardware_concurrency();
    std::vector<std::thread> threads;

    std::cout << "Starting brute force with " << numThreads << " threads..." << std::endl;

    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back(bruteForceThread, startKey, endKey, targetAddress, i, numThreads);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    if (found) {
        std::cout << "Private key found: " << bytesToHex(foundKey) << std::endl;
    } else {
        std::cout << "Brute force completed without finding the target address." << std::endl;
    }

    return 0;
}

// Implement the remaining functions (base58Encode, bytesToHex, sha256, ripemd160) as in your original code

std::string deriveBitcoinAddress(const std::vector<unsigned char>& privateKey, bool compressed) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_EC, NULL, privateKey.data(), privateKey.size());
    if (!pkey) {
        std::cerr << "Error creating private key" << std::endl;
        return "";
    }

    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) {
        std::cerr << "Error getting EC key" << std::endl;
        EVP_PKEY_free(pkey);
        return "";
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub_key = EC_POINT_new(group);
    if (!pub_key) {
        std::cerr << "Error creating EC_POINT for public key" << std::endl;
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return "";
    }

    if (!EC_POINT_mul(group, pub_key, EC_KEY_get0_private_key(ec_key), NULL, NULL, NULL)) {
        std::cerr << "Error computing public key" << std::endl;
        EC_POINT_free(pub_key);
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return "";
    }

    size_t pub_key_len = EC_POINT_point2oct(group, pub_key, 
        compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED,
        NULL, 0, NULL);
    std::vector<unsigned char> pubKey(pub_key_len);
    EC_POINT_point2oct(group, pub_key, 
        compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED,
        pubKey.data(), pub_key_len, NULL);

    EC_POINT_free(pub_key);
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);

    // Derive Bitcoin address from public key
    std::vector<unsigned char> pubKeyHash = ripemd160(sha256(pubKey));

    std::vector<unsigned char> addressBytes = {0x00};
    addressBytes.insert(addressBytes.end(), pubKeyHash.begin(), pubKeyHash.end());

    std::vector<unsigned char> checksum = sha256(sha256(addressBytes));
    addressBytes.insert(addressBytes.end(), checksum.begin(), checksum.begin() + 4);

    return base58Encode(addressBytes);
}