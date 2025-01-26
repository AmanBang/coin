#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
#include <iomanip>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>
#include <openssl/evp.h>
#include <algorithm>

// BELOW IS PRIVATE KEY CODE


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



// BELOW IS BRUTE FORCE CODE

std::string int_to_string(int number) {
  std::stringstream ss; 
  ss << number; 
  return ss.str(); 
}
std::string int_to_hex(int number) {
  std::stringstream ss;
  ss << std::hex << std::uppercase << number; 
  return ss.str();
}
static std::string hexToString(int hexValue) {
        std::stringstream ss;
        ss << "0x" << std::uppercase << std::hex << hexValue;
        return ss.str();
    }
 // Convert string to hex number
    static int stringToHex(const std::string& hexString) {
        // Convert to integer
        int hexValue;
        std::stringstream ss;
        ss << std::hex << hexString;
        ss >> hexValue;
        
        return hexValue;
    }
int maxValue(int value) {
    std::string result(value-1, 'F');
    // std::cout << "0x"+ result << std::endl;
    return stringToHex(result);
}

std::string pflh(int length, int value) {
    if (length <= 0) {
        return "Invalid length. Please enter a positive integer.";
    }
    std::stringstream ss;
    ss << std::hex << std::setw(length) << std::setfill('0') << value << std::endl;
    return ss.str();
}

std::string pflh_key( int value) {
    std::stringstream ss;
    ss << std::hex << std::setw(64) << std::setfill('0') << value << std::endl;
    return ss.str();
}


int main() {

    std::string start_value = "11";
    std::string end_value = "31";
    std::string Address2= "1E6NuFjCi27W5zoXg8TRdcSRq84zJeBW3k";
    std::string Address1 = "19ZewH8Kk1PDbSNdJ97FP4EiCjTRaZMZQA";
    int start_first_digit = start_value[0] - '0';
    int lcd = start_value.size(); 
    int current_value = 0;
    for (int first_digit = start_first_digit; first_digit < 10; ++first_digit)
    {
        int max_value = maxValue( lcd );
        // std::cout << std::hex<< max_value << std::endl;
      for (int rest_digits = 0; rest_digits <= max_value; ++rest_digits) {
        current_value = stringToHex(int_to_string(first_digit) +  (pflh(lcd-1,rest_digits)));
        // std::cout << pflh_key(current_value) << std::endl;

        if(privateKeyToBitcoinAddress(pflh_key(current_value), true) == Address1){
          std::cout << "Found a match: " << pflh_key(current_value) << std::endl;
          std::cout << "Address : " <<  Address1 << std::endl;
          break;
        }
        if (first_digit == 9 && rest_digits == max_value)
        {
          first_digit = 1;
          rest_digits = -1;
          lcd= lcd +1;
        }
        if (current_value >= stringToHex(end_value)){
          break;
        }
        
      }
       
    }

    return 0;
}
