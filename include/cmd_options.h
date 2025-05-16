#pragma once

#include <boost/program_options.hpp>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>

namespace CryptoGuard {

class ProgramOptions {
public:
    static constexpr size_t kMinPasswordLen = 4;
    static_assert(kMinPasswordLen > 0, "Set minimal password len upper than 0");

    ProgramOptions();
    ~ProgramOptions();

    enum class ERROR : int {
        EALL_OK = 0,
        EUNSUPPORT_CMD = 1,
        EINPUT_FILE_ERROR = 3,
        EOUT_PATH_ERROR = 4,
        ECMD_IS_MISS = 5,
        EWRONG_PASSWORD = 6,
        ECOMMON_ERROR = 7,
        EUNKNOWN_ERROR = -1
    };

    using ParseResult = std::tuple<bool, ERROR>;

    enum class COMMAND_TYPE {
        ENCRYPT,
        DECRYPT,
        CHECKSUM,
    };

    [[nodiscard("Should not ingnore result!")]] ParseResult Parse(int argc, char *argv[]);

    COMMAND_TYPE GetCommand() const { return command_; }
    const std::filesystem::path &GetInputFile() const { return inputFile_; }
    const std::filesystem::path &GetOutputFile() const { return outputFile_; }
    std::string_view GetPassword() const { return password_; }

    void PrintOptionsUsage();
    void PrintError(const ERROR &e);
    static bool IsError(ERROR e) { return e != ERROR::EALL_OK; }
    static int GetErrorCode(ERROR e) { return static_cast<int>(e); }

private:
    static std::string_view GetErrorPrefix(const ERROR &e);
    COMMAND_TYPE command_;
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
        {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
    };
    static std::unordered_map<ERROR, std::string_view> errorMapping_;

    std::filesystem::path inputFile_;
    std::filesystem::path outputFile_;
    std::string password_;

    std::string commandText_;

    boost::program_options::options_description desc_;

    std::string lastCommonError_;
};

}  // namespace CryptoGuard
