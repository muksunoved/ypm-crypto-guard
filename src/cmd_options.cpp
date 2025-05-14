#include "cmd_options.h"
#include <boost/program_options/variables_map.hpp>
#include <filesystem>
#include <iostream>
#include <ostream>
#include <print>
#include <string_view>
#include <tuple>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    namespace popt = boost::program_options;
    namespace fs = std::filesystem;

    desc_.add_options()("help,h", "produce help message")("input,i", popt::value<fs::path>(&inputFile_),
                                                          "input file path")(
        "output,o", popt::value<fs::path>(&outputFile_),
        "output file path")("password,p", popt::value<std::string>(&password_),
                            "password")("command,c", popt::value<std::string>(&commandText_),
                                        "run one of next command: \t"
                                        "encrypt, decrypt, checksum");
}

ProgramOptions::~ProgramOptions() = default;

std::tuple<bool, bool> ProgramOptions::Parse(int argc, char *argv[]) {
    namespace popt = boost::program_options;
    namespace fs = std::filesystem;

    const bool kShouldGoodExit = true;

    auto check_and_set_parameters = [&]() {
        auto it = commandMapping_.find(commandText_);
        if (it == commandMapping_.end()) {
            std::println("command: {} not supported", commandText_);
            return false;
        } else {
            command_ = it->second;
        }
        auto status = fs::status(inputFile_);
        if (!fs::exists(status)) {
            std::println("input file: {} not exist", inputFile_.c_str());
            return false;
        }
        if (!fs::is_regular_file(status)) {
            std::println("input file: {} is not regular file", inputFile_.c_str());
            return false;
        }
        auto parent_path = outputFile_.parent_path();
        status = fs::status(parent_path);
        if (!fs::is_directory(status)) {
            std::println("output directory of {} is not exist or not directory", parent_path.c_str());
            return false;
        }
        return true;
    };
    popt::variables_map vm;
    popt::store(popt::parse_command_line(argc, argv, desc_), vm);
    popt::notify(vm);

    if (vm.count("help")) {
        std::cout << desc_ << std::endl;
        return std::make_tuple(kShouldGoodExit, true);
    }
    return std::make_tuple(!kShouldGoodExit, check_and_set_parameters());
}

}  // namespace CryptoGuard
