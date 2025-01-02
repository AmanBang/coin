#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

// Base58 character set
static const char* base58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Function to perform Base58Check encoding
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

std::string deriveBitcoinAddress(const std::vector<unsigned char>& privateKey) {
    std::cout << "Deriving Bitcoin address for private key: " << bytesToHex(privateKey) << std::endl;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp256k1) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        // Handle error
        std::cerr << "Error during key generation" << std::endl;
        EVP_PKEY_CTX_free(pctx);
        return "";
    }
    EVP_PKEY_CTX_free(pctx);

    // Set the private key
    if (EVP_PKEY_set_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                              BN_bin2bn(privateKey.data(), privateKey.size(), NULL)) <= 0) {
        // Handle error
        std::cerr << "Error setting private key" << std::endl;
        EVP_PKEY_free(pkey);
        return "";
    }

    // Get the public key
    size_t pub_len = 0;
    unsigned char *pub_key = NULL;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_len) <= 0 ||
        (pub_key = (unsigned char*)OPENSSL_malloc(pub_len)) == NULL ||
        EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub_key, pub_len, &pub_len) <= 0) {
        // Handle error
        std::cerr << "Error getting public key" << std::endl;
        EVP_PKEY_free(pkey);
        OPENSSL_free(pub_key);
        return "";
    }

    std::cout << "Public key derived successfully" << std::endl;

    // Perform SHA-256 and RIPEMD-160
    std::vector<unsigned char> pubKey(pub_key, pub_key + pub_len);
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
    OPENSSL_free(pub_key);

    std::cout << "Bitcoin address derived: " << bitcoinAddress << std::endl;

    // return bitcoinAddress;
    return base58Encode(bitcoinAddress);

}

// Brute force through the keyspace
void bruteForce(const std::vector<unsigned char>& startKey, const std::vector<unsigned char>& endKey, const std::string& targetAddress) {
    std::vector<unsigned char> currentKey = startKey;

    std::cout << "Starting brute force..." << std::endl;

    // Limit the first character to numbers (0–9)
    for (unsigned char firstChar = 0x00; firstChar <= 0x39; ++firstChar) {  // ASCII '0' to '9'
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

    std::cout << "Brute force completed without finding the target address." << std::endl;
}

int main() {
    // Define the starting and ending keys (replace with the actual range)
  //  std::vector<unsigned char> startKey = {0x28, 0x32, 0xed, 0x74, 0xf2, 0xb5, 0xe3, 0x5e, 0xee};
    std::vector<unsigned char> startKey = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};
   // std::vector<unsigned char> endKey = {0x34, 0x9b, 0x84, 0xb6, 0x43, 0x1a, 0x6c, 0x4e, 0xf1};
std::vector<unsigned char> endKey = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x02
};
    // Target Bitcoin address (replace with the actual challenge address)
    std::string targetAddress = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";

    // Start brute force
    bruteForce(startKey, endKey, targetAddress);

    return 0;
}
