#include "cmd_options.h"
#include <boost/program_options/variables_map.hpp>
#include <filesystem>
#include <iostream>
#include <print>
#include <string_view>

namespace CryptoGuard {

std::unordered_map<ProgramOptions::ERROR, std::string_view> ProgramOptions::errorMapping_ = {
    // clang-format off
    {ERROR::EALL_OK,                ""                              },
    {ERROR::EUNSUPPORT_CMD,         "unsupported command"       },
    {ERROR::EINPUT_FILE_ERROR,      "input file error"          },
    {ERROR::EOUT_PATH_ERROR,        "output file path error"    },
    {ERROR::ECMD_IS_MISS,           "option command missing"    },
    {ERROR::EWRONG_PASSWORD,        "missing or wrong password" },
    {ERROR::EINOUT_SAME_FILE,       "output file same as input" },
    {ERROR::EUNKNOWN_ERROR,         "unknown error"             },
    // clang-format on

};

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    namespace popt = boost::program_options;
    namespace fs = std::filesystem;
    // clang-format off
    desc_.add_options()("help,h", "produce help message")
        ("input,i", popt::value<fs::path>(&inputFile_), "input file path")
        ("output,o", popt::value<fs::path>(&outputFile_), "output file path")
        ("password,p", popt::value<std::string>(&password_),"password")
        ("command,c", popt::value<std::string>(&commandText_),
                                     "run one of next command: \t encrypt, decrypt, checksum");
    // clang-format on
}

ProgramOptions::~ProgramOptions() = default;

ProgramOptions::ParseResult ProgramOptions::Parse(int argc, char *argv[]) {
    namespace popt = boost::program_options;
    namespace fs = std::filesystem;

    const bool kShouldGoodExit = true;

    auto check_and_set_parameters = [&]() {
        if (commandText_.empty()) {
            return ERROR::ECMD_IS_MISS;
        }

        auto it = commandMapping_.find(commandText_);

        if (it == commandMapping_.end()) {
            return ERROR::EUNSUPPORT_CMD;
        } else {
            command_ = it->second;
        }
        if (command_ == COMMAND_TYPE::ENCRYPT) {
            if (password_.length() < kMinPasswordLen + 1) {
                return ERROR::EWRONG_PASSWORD;
            }
        }

        auto status = fs::status(inputFile_);
        if (!fs::exists(status) || !fs::is_regular_file(status)) {
            return ERROR::EINPUT_FILE_ERROR;
        }

        if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {

            auto parent_path = outputFile_.parent_path();
            status = fs::status(parent_path);

            if (!fs::is_directory(status)) {
                return ERROR::EOUT_PATH_ERROR;
            }
            if (inputFile_ == outputFile_) {
                return ERROR::EINOUT_SAME_FILE;
            }
        }
        return ERROR::EALL_OK;
    };

    try {
        popt::variables_map vm;
        popt::store(popt::parse_command_line(argc, argv, desc_), vm);
        popt::notify(vm);

        if (vm.count("help")) {
            return ParseResult(kShouldGoodExit, ERROR::EALL_OK);
        }

    } catch (std::exception &e) {
        lastCommonError_ = e.what();
        return ParseResult(!kShouldGoodExit, ERROR::ECOMMON_ERROR);
    }
    return ParseResult(!kShouldGoodExit, check_and_set_parameters());
}

void ProgramOptions::PrintOptionsUsage() { desc_.print(std::cout); }

std::string_view ProgramOptions::GetErrorPrefix(const ERROR &e) {
    if (e == ERROR::EALL_OK) {
        return " ";
    }
    return "Error: ";
}

void ProgramOptions::PrintError(const ERROR &e) {
    auto s = errorMapping_.at(ProgramOptions::ERROR::EUNKNOWN_ERROR);

    auto it = errorMapping_.find(e);
    if (it != errorMapping_.end()) {
        s = (e == ERROR::ECOMMON_ERROR) ? lastCommonError_ : it->second;
    }
    println("{} {}", GetErrorPrefix(e), s);
}

}  // namespace CryptoGuard
