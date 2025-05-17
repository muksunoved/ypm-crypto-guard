
#include "crypto_guard_ctx.h"
#include <iostream>
#include <istream>
#include <memory>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace CryptoGuard {

struct CryptoGuardCtx::Impl {
    Impl() { OpenSSL_add_all_algorithms(); };
    ~Impl() { EVP_cleanup(); }

    using ERROR = CryptoGuardCtx::CryptoGuardException::ERROR;

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
    using EvpCipherCtxUptr =
        std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;
    using EvpMdCtxUptr = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); })>;

    std::pair<bool, size_t> GetNexData(std::iostream &inStream, std::vector<unsigned char> &inBuf,
                                       size_t request_count) {
        size_t real_count = 0;

        while (!inStream.eof() && real_count != request_count) {
            inStream >> inBuf[real_count];
            std::cout << 1 << std::hex << "0x" << int(inBuf[real_count]) << std::dec << std::endl;
            real_count++;
        }
        return std::make_pair(inStream.eof(), real_count);
    }

    void EncryptDecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        EvpCipherCtxUptr ctx(EVP_CIPHER_CTX_new());
        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;

        if (!ctx) {
            throw CryptoGuardException(ERROR::ECIPHER_INIT, "Create cipher context failed.");
        }

        if (!EVP_CipherInit_ex(&*ctx, params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)) {
            throw CryptoGuardException(ERROR::ECIPHER_INIT, "Cipher initialization failed.");
        }

        int cipher_block_size = EVP_CIPHER_block_size(params.cipher);

        std::vector<unsigned char> outBuf(16 + cipher_block_size);
        std::vector<unsigned char> inBuf(16);
        int outLen;

        size_t retries = 0;

        while (GetNexData(inStream, inBuf, 16).second) {
            if (!EVP_CipherUpdate(&*ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16))) {
                ThrowError(ERROR::ECIPHER_UPDATE, "Cipher update failed.");
            }
            for (int i = 0; i < outLen; ++i) {
                outStream.putback(outBuf[i]);
            }
            ++retries;
        }
        if (retries) {
            if (EVP_CipherFinal_ex(&*ctx, outBuf.data(), &outLen)) {
                ThrowError(ERROR::ECIPHER_FINALIZE, "Cipher finalization failed");
            }
        } else {
            ThrowError(ERROR::EEMPTY_INPUT_FILE, "Empty input file");
        }
    }
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        EncryptDecryptFile(inStream, outStream, password);
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        EncryptDecryptFile(inStream, outStream, password);
    }

    std::string CalculateChecksum(std::iostream &inStream) {
        std::vector<unsigned char> inBuf(16);
        size_t retries = 0;
        unsigned int md_len;

        unsigned char md_value[EVP_MAX_MD_SIZE];
        const EVP_MD *md = EVP_sha256();

        EvpMdCtxUptr ctx(EVP_MD_CTX_new());

        if (!ctx) {
            ThrowError(ERROR::EDIGET_CREATE, "Message digest create failed.");
        }

        if (!EVP_DigestInit_ex2(&*ctx, md, NULL)) {
            ThrowError(ERROR::EDIGEST_INIT, "Message digest initialization failed.");
        }
        while (GetNexData(inStream, inBuf, 16).second) {
            if (!EVP_DigestUpdate(&*ctx, inBuf.data(), static_cast<int>(16))) {
                ThrowError(ERROR::EDIGEST_UPDATE, "Message digest update failed");
            }
            ++retries;
        }
        if (retries) {
            if (!EVP_DigestFinal_ex(&*ctx, md_value, &md_len)) {
                ThrowError(ERROR::EDIGEST_FINALISE, "Message digest finalization failed.");
            }
        } else {
            CryptoGuardException(ERROR::EEMPTY_INPUT_FILE, "Empty input file");
        }

        std::string result;
        std::stringstream helper(result);

        for (int i = 0; i < md_len; ++i) {
            helper << std::hex << md_value[i];
        }
        return result;
    }
    void ThrowError(CryptoGuardCtx::CryptoGuardException::ERROR e, const std::string &error_text) {
        last_error_ = e;
        throw CryptoGuardCtx::CryptoGuardException(e, error_text);
    }

    CryptoGuardException::ERROR last_error_ = ERROR::EALL_OK;
};

CryptoGuardCtx::CryptoGuardCtx() { pImpl_ = std::make_unique<CryptoGuardCtx::Impl>(); }

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

CryptoGuardCtx::ERROR CryptoGuardCtx::GetLastError() { return pImpl_->last_error_; }

}  // namespace CryptoGuard
