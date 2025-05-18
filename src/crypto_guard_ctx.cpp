
#include "crypto_guard_ctx.h"
#include <iostream>
#include <istream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace CryptoGuard {

struct CryptoGuardCtx::Impl {
    const size_t kMaxCryptErrorList = 10;
    Impl(){};
    ~Impl() {}

    using ERROR = CryptoGuardException::ERROR;

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
            ThrowError(ERROR::ECHIPHER_CREATE_KEY, "Failed to create a key from password");
        }

        return params;
    }
    using EvpCipherCtxUptr = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) {
                                                 EVP_CIPHER_CTX_free(ctx);
                                                 EVP_cleanup();
                                             })>;

    using EvpMdCtxUptr = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ctx) {
                                             EVP_MD_CTX_free(ctx);
                                             EVP_cleanup();
                                         })>;

    std::pair<bool, size_t> GetNexData(std::iostream &inStream, std::vector<unsigned char> &inBuf,
                                       size_t request_count) {
        size_t real_count = 0;

        char c;
        while (real_count != request_count) {
            inStream.get(c);
            if (inStream.eof() || inStream.fail()) {
                break;
            }
            inBuf[real_count++] = c;
        }
        return std::make_pair(inStream.eof(), real_count);
    }

    void EncryptDecryptFile(std::iostream &inStream, std::iostream &outStream, const AesCipherParams &params) {

        OpenSSL_add_all_algorithms();

        ERR_clear_error();
        EvpCipherCtxUptr ctx(EVP_CIPHER_CTX_new());

        if (!ctx) {
            ThrowError(ERROR::ECIPHER_INIT, "Create cipher context failed.\n" + GetCryptErrors(kMaxCryptErrorList));
        }

        if (!EVP_CipherInit_ex(&*ctx, params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)) {
            ThrowError(ERROR::ECIPHER_INIT, "Cipher initialization failed.\n" + GetCryptErrors(kMaxCryptErrorList));
        }

        int cipher_block_size = EVP_CIPHER_block_size(params.cipher);

        std::vector<unsigned char> outBuf(1024 + cipher_block_size);
        std::vector<unsigned char> inBuf(1024);
        int outLen = 0;

        size_t retries = 0;
        std::pair<bool, size_t> result;

        while ((result = GetNexData(inStream, inBuf, 1024)).second) {
            if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), result.second)) {
                ThrowError(ERROR::ECIPHER_UPDATE, "Cipher update failed.\n" + GetCryptErrors(kMaxCryptErrorList));
            }
            for (int i = 0; i < outLen; ++i) {
                outStream.put(outBuf[i]);
            }
            ++retries;
        }
        if (retries) {
            if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
                ThrowError(ERROR::ECIPHER_FINALIZE, "Cipher finalize failed\n" + GetCryptErrors(kMaxCryptErrorList));
            }
            for (int i = 0; i < outLen; ++i) {
                outStream.put(outBuf[i]);
            }
        } else {
            ThrowError(ERROR::EEMPTY_INPUT_FILE, "Empty input file\n");
        }
    }
    std::string GetCryptErrors(int max_list) {
        std::string error_list;
        char buf[64];

        auto e = ERR_get_error();
        while (max_list--) {
            if (!e)
                break;

            ERR_error_string_n(e, buf, 64);
            error_list += std::string(buf) + "\n";
        }
        return error_list;
    }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;
        EncryptDecryptFile(inStream, outStream, params);
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 0;
        EncryptDecryptFile(inStream, outStream, params);
    }

    std::string CalculateChecksum(std::iostream &inStream) {
        OpenSSL_add_all_algorithms();

        std::vector<unsigned char> inBuf(16);
        size_t retries = 0;
        unsigned int md_len;

        unsigned char md_value[EVP_MAX_MD_SIZE];
        const EVP_MD *md = EVP_sha256();

        EvpMdCtxUptr ctx(EVP_MD_CTX_new());

        if (!ctx) {
            ThrowError(ERROR::EDIGET_CREATE, "Message digest create failed.\n" + GetCryptErrors(kMaxCryptErrorList));
        }

        if (!EVP_DigestInit_ex2(&*ctx, md, NULL)) {
            ThrowError(ERROR::EDIGEST_INIT,
                       "Message digest initialization failed.\n" + GetCryptErrors(kMaxCryptErrorList));
        }
        while (GetNexData(inStream, inBuf, 16).second) {
            if (!EVP_DigestUpdate(&*ctx, inBuf.data(), static_cast<int>(16))) {
                ThrowError(ERROR::EDIGEST_UPDATE,
                           "Message digest update failed\n" + GetCryptErrors(kMaxCryptErrorList));
            }
            ++retries;
        }
        if (retries) {
            if (!EVP_DigestFinal_ex(&*ctx, md_value, &md_len)) {
                ThrowError(ERROR::EDIGEST_FINALISE,
                           "Message digest finalization failed.\n" + GetCryptErrors(kMaxCryptErrorList));
            }
        } else {
            ThrowError(ERROR::EEMPTY_INPUT_FILE, "Empty input file\n");
        }

        std::stringstream helper;

        for (int i = 0; i < md_len; ++i) {
            helper << std::hex << std::uint32_t(md_value[i]);
        }
        return helper.str();
    }

    void ThrowError(CryptoGuardException::ERROR e, const std::string &error_text) {
        last_error_ = e;
        throw CryptoGuardException(e, error_text);
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
