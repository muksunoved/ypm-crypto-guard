#pragma once

#include <experimental/propagate_const>
#include <memory>
#include <stdexcept>
#include <string>

namespace CryptoGuard {

class CryptoGuardCtx {
public:
    class CryptoGuardException : public std::runtime_error {
    public:
        enum class ERROR {
            EALL_OK,
            ECIPHER_CREATE,
            ECIPHER_INIT,
            ECIPHER_UPDATE,
            ECIPHER_FINALIZE,
            EEMPTY_INPUT_FILE,
            EDIGET_CREATE,
            EDIGEST_INIT,
            EDIGEST_UPDATE,
            EDIGEST_FINALISE,
        };

        CryptoGuardException(ERROR e, const std::string &message) : std::runtime_error("") {
            error_code_ = e;
            message_ = message;
        }
        const char *what() const throw() override { return message_.c_str(); }
        ERROR get_error() { return error_code_; }

    private:
        ERROR error_code_ = ERROR::EALL_OK;
        std::string message_;
    };

    using ERROR = CryptoGuardException::ERROR;

    CryptoGuardCtx();
    ~CryptoGuardCtx();

    CryptoGuardCtx(const CryptoGuardCtx &) = delete;
    CryptoGuardCtx &operator=(const CryptoGuardCtx &) = delete;

    CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
    CryptoGuardCtx &operator=(CryptoGuardCtx &&) noexcept = default;

    // API
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);
    void ThrowError(CryptoGuardException::ERROR e, const std::string &error_txt);
    ERROR GetLastError();

private:
    class Impl;
    std::experimental::propagate_const<std::unique_ptr<Impl>> pImpl_;
};

}  // namespace CryptoGuard
