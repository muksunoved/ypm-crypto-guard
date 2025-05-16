
#include "cmd_options.h"
#include <gtest/gtest.h>

namespace CryptoGuard {

class ProgramOptionsTest : public ::testing::Test {
public:
    ProgramOptions options;
};

TEST_F(ProgramOptionsTest, ShouldGetGoodExitIfHelpOptionPresent) {
    std::vector<char *> fake_argv{
        (char *)"test ", /* Program name */
        (char *)"--help" /* Single parameter */
    };

    auto [result, error_code] = options.Parse(fake_argv.size(), fake_argv.data());

    EXPECT_TRUE(result);
    EXPECT_EQ(error_code, ProgramOptions::ERROR::EALL_OK);
}

TEST_F(ProgramOptionsTest, ShouldSetErrorIfCmdOptionNotPresent) {
    std::vector<char *> fake_argv{
        (char *)"test ",        /* Program name */
        (char *)"--input",      /* input parameter */
        (char *)"/bla/bla/in",  /* fake path to input file */
        (char *)"--output",     /*  output parameter  */
        (char *)"/bla/bla/out", /* fake path to output file */
    };

    auto [result, error_code] = options.Parse(fake_argv.size(), fake_argv.data());

    EXPECT_FALSE(result);
    EXPECT_EQ(error_code, ProgramOptions::ERROR::ECMD_IS_MISS);
}

TEST_F(ProgramOptionsTest, ShouldGetErrorIfEncryptAndPasswordTooSmall) {
    std::vector<char *> fake_argv{
        (char *)"test ",      /* Program name */
        (char *)"--command",  /* command option */
        (char *)"encrypt",    /* command */
        (char *)"--password", /*  password option  */
        (char *)"1234",       /* small length password */
    };

    auto [result, error_code] = options.Parse(fake_argv.size(), fake_argv.data());

    EXPECT_FALSE(result);
    EXPECT_EQ(error_code, ProgramOptions::ERROR::EWRONG_PASSWORD);
}

TEST_F(ProgramOptionsTest, ShouldGetErrorIfInputFilePathEmpty) {
    std::vector<char *> fake_argv{
        (char *)"test ",      /* Program name */
        (char *)"--command",  /* command option */
        (char *)"encrypt",    /* command */
        (char *)"--password", /*  password option  */
        (char *)"12345",      /* small length password */
        (char *)"--input",    /* input file option */
        (char *)"",           /* empty file name */
    };

    auto [result, error_code] = options.Parse(fake_argv.size(), fake_argv.data());

    EXPECT_FALSE(result);
    EXPECT_EQ(error_code, ProgramOptions::ERROR::ECOMMON_ERROR);
}

TEST_F(ProgramOptionsTest, ShouldGetErrorIfInputFileNotExist) {
    std::vector<char *> fake_argv{
        (char *)"test ",        /* Program name */
        (char *)"--command",    /* command option */
        (char *)"encrypt",      /* command */
        (char *)"--password",   /*  password option  */
        (char *)"12345",        /* small length password */
        (char *)"--input",      /* input file option */
        (char *)"/bla/bla/bla", /* this file not exist */
    };

    auto [result, error_code] = options.Parse(fake_argv.size(), fake_argv.data());

    EXPECT_FALSE(result);
    EXPECT_EQ(error_code, ProgramOptions::ERROR::EINPUT_FILE_ERROR);
}

TEST_F(ProgramOptionsTest, ShouldGetErrorIfOutputFileDirNotExist) {
    std::vector<char *> fake_argv{
        (char *)"test ",               /* Program name */
        (char *)"--command",           /* command option */
        (char *)"encrypt",             /* command */
        (char *)"--password",          /*  password option  */
        (char *)"12345",               /* small length password */
        (char *)"--input",             /* input file option */
        (char *)"./CryptoGuard_tests", /* any real exist file */
        (char *)"--output",            /* output file option */
        (char *)"./bla/bla.out",       /* this dir do not exist */
    };

    auto [result, error_code] = options.Parse(fake_argv.size(), fake_argv.data());

    EXPECT_FALSE(result);
    EXPECT_EQ(error_code, ProgramOptions::ERROR::EOUT_PATH_ERROR);
}

TEST_F(ProgramOptionsTest, ShouldSetErrorIfCmdIsUnknown) {
    std::vector<char *> fake_argv{
        (char *)"test ",               /* Program name */
        (char *)"--command",           /* command option */
        (char *)"blablacommand",       /* unsupported command */
        (char *)"--password",          /*  password option  */
        (char *)"12345",               /* small length password */
        (char *)"--input",             /* input file option */
        (char *)"./CryptoGuard_tests", /* any real exist file */
    };

    auto [result, error_code] = options.Parse(fake_argv.size(), fake_argv.data());

    EXPECT_FALSE(result);
    EXPECT_EQ(error_code, ProgramOptions::ERROR::EUNSUPPORT_CMD);
}

}  // namespace CryptoGuard
