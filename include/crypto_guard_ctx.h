#pragma once

#include <crypto_guard_error.h>
#include <experimental/propagate_const>
#include <memory>
#include <stdexcept>
#include <string>

namespace CryptoGuard {

class CryptoGuardCtx {
public:
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
