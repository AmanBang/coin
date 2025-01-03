#include <iostream>
#include <string>
#include <vector>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstdint>

// Base58 characters
const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Function to convert hex string to byte vector
std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.length() / 2);
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Function to perform SHA-256 hashing
std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data.data(), data.size());
    SHA256_Final(hash.data(), &sha256_ctx);
    return hash;
}

// Function to perform RIPEMD-160 hashing
std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160_CTX ripemd_ctx;
    RIPEMD160_Init(&ripemd_ctx);
    RIPEMD160_Update(&ripemd_ctx, data.data(), data.size());
    RIPEMD160_Final(hash.data(), &ripemd_ctx);
    return hash;
}

// Function to encode a byte vector to Base58
std::string base58_encode(const std::vector<unsigned char>& data) {
    // Convert byte vector to bigint
    BIGNUM* bn = BN_new();
    BN_zero(bn);
    for (size_t i = 0; i < data.size(); ++i) {
        BN_mul_word(bn, 256);
        BN_add_word(bn, data[i]);
    }

    // Convert bigint to Base58 string
    std::string encoded;
    while (!BN_is_zero(bn)) {
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* rem = BN_new();
        BIGNUM* div = BN_new();
        BN_div(div, rem, bn, BN_value_one(), ctx); // Placeholder, needs proper division by 58
        // Since OpenSSL doesn't have direct support for base58 division, implement manually or use another library
        // For simplicity, using a different approach below
        BN_free(rem);
        BN_free(div);
        BN_CTX_free(ctx);
        break; // Placeholder break
    }

    BN_free(bn);
    // Placeholder: Implement proper Base58 encoding or use an existing library
    return encoded;
}

// Function to count leading zeros
int count_leading_zeros(const std::vector<unsigned char>& data) {
    int count = 0;
    for (auto byte : data) {
        if (byte == 0x00)
            count++;
        else
            break;
    }
    return count;
}

// Function to encode to Base58 (correct implementation)
std::string base58_encode_correct(const std::vector<unsigned char>& input) {
    // Convert byte array to a big integer
    BIGNUM* bn = BN_new();
    BN_zero(bn);
    for (auto byte : input) {
        BN_shift_left(bn, bn, 8);
        BN_add_word(bn, byte);
    }

    // 58 base
    BIGNUM* bn58 = BN_new();
    BN_set_word(bn58, 58);
    BIGNUM* bn0 = BN_new();
    BN_zero(bn0);

    std::string encoded = "";

    BIGNUM* remainder = BN_new();
    BIGNUM* tmp = BN_new();

    while (BN_cmp(bn, bn0) > 0) {
        BN_div(tmp, remainder, bn, bn58, BN_CTX_new());
        unsigned long rem = BN_get_word(remainder);
        encoded += BASE58_ALPHABET[rem];
        BN_copy(bn, tmp);
    }

    // Handle leading zeros
    int leading = count_leading_zeros(input);
    for (int i = 0; i < leading; ++i)
        encoded += BASE58_ALPHABET[0];

    // Reverse the string
    std::reverse(encoded.begin(), encoded.end());

    // Cleanup
    BN_free(bn);
    BN_free(bn58);
    BN_free(bn0);
    BN_free(remainder);
    BN_free(tmp);

    return encoded;
}

// Function to generate Base58Check encoding
std::string base58check_encode(const std::vector<unsigned char>& payload) {
    // Compute checksum: double SHA-256
    std::vector<unsigned char> checksum_full = sha256(sha256(payload));
    std::vector<unsigned char> checksum(checksum_full.begin(), checksum_full.begin() + 4);

    // Append checksum to payload
    std::vector<unsigned char> address_with_checksum = payload;
    address_with_checksum.insert(address_with_checksum.end(), checksum.begin(), checksum.end());

    // Encode to Base58
    return base58_encode_correct(address_with_checksum);
}

// Function to convert byte array to hex string
std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    for(auto byte : bytes)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    return ss.str();
}

// Function to convert integer to byte array (big endian)
std::vector<unsigned char> int_to_bytes(unsigned long x, size_t size) {
    std::vector<unsigned char> bytes(size, 0);
    for(int i = size -1; i >=0 && x >0; --i){
        bytes[i] = x & 0xFF;
        x >>=8;
    }
    return bytes;
}

// Function to generate Bitcoin address from private key
std::string private_key_to_bitcoin_address(const std::string& private_key_hex, bool compressed=true) {
    // Convert private key from hex to bytes
    std::vector<unsigned char> private_key = hex_to_bytes(private_key_hex);

    // Create EC_KEY object
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if(ec_key == nullptr){
        std::cerr << "Error creating EC_KEY object." << std::endl;
        exit(1);
    }

    // Convert private key to BIGNUM
    BIGNUM* priv_key_bn = BN_bin2bn(private_key.data(), private_key.size(), nullptr);
    if(priv_key_bn == nullptr){
        std::cerr << "Error converting private key to BIGNUM." << std::endl;
        exit(1);
    }

    // Assign private key to EC_KEY
    if(!EC_KEY_set_private_key(ec_key, priv_key_bn)){
        std::cerr << "Error setting private key." << std::endl;
        exit(1);
    }

    // Get the group
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    if(group == nullptr){
        std::cerr << "Error getting EC_GROUP." << std::endl;
        exit(1);
    }

    // Get the generator point
    const EC_POINT* generator = EC_GROUP_get0_generator(group);
    if(generator == nullptr){
        std::cerr << "Error getting generator point." << std::endl;
        exit(1);
    }

    // Calculate public key point = priv_key * generator
    EC_POINT* pub_key_point = EC_POINT_new(group);
    if(!EC_POINT_mul(group, pub_key_point, priv_key_bn, nullptr, nullptr, nullptr)){
        std::cerr << "Error computing public key point." << std::endl;
        exit(1);
    }

    // Create a new EC_KEY for the public key
    EC_KEY_set_public_key(ec_key, pub_key_point);

    // Encode the public key
    int pub_key_len;
    std::vector<unsigned char> pub_key_bytes;
    if(compressed){
        pub_key_len = i2o_ECPublicKey(ec_key, nullptr);
        pub_key_bytes.resize(pub_key_len);
        unsigned char* pub_key_ptr = pub_key_bytes.data();
        i2o_ECPublicKey(ec_key, &pub_key_ptr);
        // Ensure it's compressed
        // Alternatively, use EC_POINT_point2oct with compressed form
        pub_key_bytes.clear();
        size_t len = EC_POINT_point2oct(group, pub_key_point, POINT_CONVERSION_COMPRESSED, nullptr, 0, nullptr);
        pub_key_bytes.resize(len);
        EC_POINT_point2oct(group, pub_key_point, POINT_CONVERSION_COMPRESSED, pub_key_bytes.data(), len, nullptr);
    }
    else{
        pub_key_len = i2o_ECPublicKey(ec_key, nullptr);
        pub_key_bytes.resize(pub_key_len);
        unsigned char* pub_key_ptr = pub_key_bytes.data();
        i2o_ECPublicKey(ec_key, &pub_key_ptr);
        // Ensure it's uncompressed
        // Alternatively, use EC_POINT_point2oct with uncompressed form
        pub_key_bytes.clear();
        size_t len = EC_POINT_point2oct(group, pub_key_point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
        pub_key_bytes.resize(len);
        EC_POINT_point2oct(group, pub_key_point, POINT_CONVERSION_UNCOMPRESSED, pub_key_bytes.data(), len, nullptr);
    }

    // Cleanup
    EC_POINT_free(pub_key_point);
    BN_free(priv_key_bn);
    EC_KEY_free(ec_key);

    // Perform SHA-256 followed by RIPEMD-160
    std::vector<unsigned char> sha256_hash = sha256(pub_key_bytes);
    std::vector<unsigned char> ripe_hash = ripemd160(sha256_hash);

    // Add network byte (0x00 for mainnet)
    std::vector<unsigned char> network_payload = {0x00};
    network_payload.insert(network_payload.end(), ripe_hash.begin(), ripe_hash.end());

    // Base58Check encode
    std::string bitcoin_address = base58check_encode(network_payload);

    return bitcoin_address;
}

int main() {
    // Example private key (mainnet)
    std::string private_key_hex = "0000000000000000000000000000000000000000000000000000001757756a93";

    // Generate Bitcoin address (compressed and uncompressed)
    std::string compressed_address = private_key_to_bitcoin_address(private_key_hex, true);
    std::string uncompressed_address = private_key_to_bitcoin_address(private_key_hex, false);

    std::cout << "Compressed Bitcoin Address: " << compressed_address << std::endl;
    std::cout << "Uncompressed Bitcoin Address: " << uncompressed_address << std::endl;

    return 0;
}