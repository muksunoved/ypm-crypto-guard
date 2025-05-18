#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <array>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}

int main(int argc, char *argv[]) {
    using namespace CryptoGuard;
    try {

        ProgramOptions options;
        auto [should_good_exit, parse_result] = options.Parse(argc, argv);

        if (should_good_exit) {
            options.PrintOptionsUsage();
            return 0;
        }

        if (ProgramOptions::IsError(parse_result)) {
            options.PrintError(parse_result);
            options.PrintOptionsUsage();
            return ProgramOptions::GetErrorCode(parse_result);
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream inFile(options.GetInputFile());
            std::fstream outFile(options.GetOutputFile());
            cryptoCtx.EncryptFile(inFile, outFile, options.GetPassword());
            std::print("File encoded successfully\n");
        } break;

        case COMMAND_TYPE::DECRYPT: {
            std::fstream inFile(options.GetInputFile());
            std::fstream outFile(options.GetOutputFile());
            cryptoCtx.DecryptFile(inFile, outFile, options.GetPassword());
            std::print("File decoded successfully\n");
        } break;

        case COMMAND_TYPE::CHECKSUM:
            std::print("Checksum: {}\n", "CHECKSUM_NOT_IMPLEMENTED");
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}