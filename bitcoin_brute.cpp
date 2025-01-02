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
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.data(), input.size());
    SHA256_Final(hash.data(), &sha256);
    return hash;
}

std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& input) {
    std::vector<unsigned char> hash(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160_CTX ripemd160;
    RIPEMD160_Init(&ripemd160);
    RIPEMD160_Update(&ripemd160, input.data(), input.size());
    RIPEMD160_Final(hash.data(), &ripemd160);
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
 EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "Error generating key" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    EVP_PKEY_CTX_free(ctx);

    if (EVP_PKEY_set1_raw_private_key(pkey, privateKey.data(), privateKey.size(), NULL) <= 0) {
        std::cerr << "Error setting private key" << std::endl;
        EVP_PKEY_free(pkey);
        return "";
    }

    unsigned char *pub_key_bytes = NULL;
    size_t pub_key_len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &pub_key_len) <= 0 ||
        (pub_key_bytes = (unsigned char*)OPENSSL_malloc(pub_key_len)) == NULL ||
        EVP_PKEY_get_raw_public_key(pkey, pub_key_bytes, &pub_key_len) <= 0) {
        std::cerr << "Error getting public key" << std::endl;
        EVP_PKEY_free(pkey);
        OPENSSL_free(pub_key_bytes);
        return "";
    }

    std::vector<unsigned char> pubKey(pub_key_bytes, pub_key_bytes + pub_key_len);
    OPENSSL_free(pub_key_bytes);
    EVP_PKEY_free(pkey);

    // Derive Bitcoin address from public key
    std::vector<unsigned char> pubKeyHash = ripemd160(sha256(pubKey));

    std::vector<unsigned char> addressBytes = {0x00};
    addressBytes.insert(addressBytes.end(), pubKeyHash.begin(), pubKeyHash.end());

    std::vector<unsigned char> checksum = sha256(sha256(addressBytes));
    addressBytes.insert(addressBytes.end(), checksum.begin(), checksum.begin() + 4);

    return base58Encode(addressBytes);
}