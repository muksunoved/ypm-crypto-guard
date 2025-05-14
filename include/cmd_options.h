#pragma once

#include <boost/program_options.hpp>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>

namespace CryptoGuard {

class ProgramOptions {
public:
    ProgramOptions();
    ~ProgramOptions();

    enum class COMMAND_TYPE {
        ENCRYPT,
        DECRYPT,
        CHECKSUM,
    };

    std::tuple<bool, bool> Parse(int argc, char *argv[]);

    COMMAND_TYPE GetCommand() const { return command_; }
    const std::filesystem::path &GetInputFile() const { return inputFile_; }
    const std::filesystem::path &GetOutputFile() const { return outputFile_; }
    std::string_view GetPassword() const { return password_; }

private:
    COMMAND_TYPE command_;
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
        {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
    };

    std::filesystem::path inputFile_;
    std::filesystem::path outputFile_;
    std::string password_;

    std::string commandText_;

    boost::program_options::options_description desc_;
};

}  // namespace CryptoGuard
