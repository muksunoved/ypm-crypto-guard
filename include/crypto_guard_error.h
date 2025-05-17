#pragma once

#include <string>

namespace CryptoGuard {

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
}  // namespace CryptoGuard
