#pragma once

#include <stdexcept>
#include <string>

namespace CryptoGuard {

class CryptoGuardException : public std::runtime_error {
public:
    // clang-format off
    enum class ERROR : int {
        EALL_OK             = 0,
        ECIPHER_CREATE      = 1,
        ECIPHER_INIT        = 2,
        ECIPHER_UPDATE      = 3,
        ECIPHER_FINALIZE    = 4,
        ECHIPHER_CREATE_KEY = 5,
        EEMPTY_INPUT_FILE   = 6,
        EDIGET_CREATE       = 7,
        EDIGEST_INIT        = 8,
        EDIGEST_UPDATE      = 9,
        EDIGEST_FINALISE    = 10,

        EUNSUPPORT_CMD      = 11,
        EINPUT_FILE_ERROR   = 12,
        EOUT_PATH_ERROR     = 13,
        ECMD_IS_MISS        = 14,
        EWRONG_PASSWORD     = 15,
        ECOMMON_ERROR       = 16,
        EINOUT_SAME_FILE    = 17,
        EUNKNOWN_ERROR      = -1
    };
    // clang-format on

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
