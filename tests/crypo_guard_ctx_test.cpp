#include "crypto_guard_ctx.h"
#include "crypto_guard_error.h"
#include <cstdio>
#include <gtest/gtest.h>
#include <ios>
#include <istream>
#include <sstream>

namespace CryptoGuard {
class CryptoGuardCtxTest : public ::testing::Test {
public:
    CryptoGuardCtx ctx;
};

TEST_F(CryptoGuardCtxTest, ShouldSetInputFileErrorIfEmpty) {
    std::stringstream fake_stream_in;
    std::stringstream fake_stream_out;
    std::string password("12345");
    char tmp;
    fake_stream_in >> tmp; /* Delete null terminator */

    ASSERT_THROW(ctx.EncryptFile(fake_stream_in, fake_stream_out, password), CryptoGuardException);
    EXPECT_EQ(ctx.GetLastError(), CryptoGuardCtx::ERROR::EEMPTY_INPUT_FILE);
}

TEST_F(CryptoGuardCtxTest, ShouldGetEncrypt) {
    std::string fake_content_in;
    std::string fake_content_out;
    std::stringstream fake_stream_in(fake_content_in);
    std::stringstream fake_stream_out;
    std::string password("12345");
    char tmp;
    fake_stream_in << "12345678900987654321";

    EXPECT_NO_THROW(ctx.EncryptFile(fake_stream_in, fake_stream_out, password));
    EXPECT_EQ(ctx.GetLastError(), CryptoGuardCtx::ERROR::EALL_OK);

    fake_content_out = fake_stream_out.str();
    EXPECT_EQ(fake_content_out.length(), 32);
}

TEST_F(CryptoGuardCtxTest, ShouldGetDecryptToSameStringAfterEncryptDecrypt) {

    std::stringstream fake_stream_in;
    std::stringstream fake_stream_out;
    std::stringstream fake_stream_same;
    std::string password("12345");
    fake_stream_in << "1234567890123445670987656678fgfgrtrtrtrtyuyuyuiui121223ghghghg";
    {
        CryptoGuardCtx ctx1;

        EXPECT_NO_THROW(ctx1.EncryptFile(fake_stream_in, fake_stream_out, password));
        EXPECT_EQ(ctx1.GetLastError(), CryptoGuardCtx::ERROR::EALL_OK);
    }
    {
        CryptoGuardCtx ctx2;

        EXPECT_NO_THROW(ctx2.DecryptFile(fake_stream_out, fake_stream_same, password));
        EXPECT_EQ(ctx2.GetLastError(), CryptoGuardCtx::ERROR::EALL_OK);
    }
    EXPECT_EQ(fake_stream_in.str(), fake_stream_same.str());
}

TEST_F(CryptoGuardCtxTest, ShouldNotMatchDecodeWithOriginalIfPassworWrong) {
    std::stringstream fake_stream_in;
    std::stringstream fake_stream_out;
    std::stringstream fake_stream_same;
    std::string password1("12345");
    std::string password2("1234a");

    fake_stream_in << "1234567890123445670987656678fgfgrtrtrtrtyuyuyuiui121223ghghghg";
    {
        CryptoGuardCtx ctx1;

        EXPECT_NO_THROW(ctx1.EncryptFile(fake_stream_in, fake_stream_out, password1));
        EXPECT_EQ(ctx1.GetLastError(), CryptoGuardCtx::ERROR::EALL_OK);
    }
    {
        CryptoGuardCtx ctx2;

        ASSERT_THROW(ctx2.DecryptFile(fake_stream_out, fake_stream_same, password2), CryptoGuardException);
        EXPECT_EQ(ctx2.GetLastError(), CryptoGuardCtx::ERROR::ECIPHER_FINALIZE);
    }
    EXPECT_NE(fake_stream_in.str(), fake_stream_same.str());
}

TEST_F(CryptoGuardCtxTest, ShouldGetDigestHexString) {
    std::stringstream fake_stream_in;
    fake_stream_in << "1234567890123445670987656678";
    const std::string Control = "8160693a26158e7fe91cc1c4d8c612b413e5dc9c4a29cd48965d91a0e97a5c";

    std::string result;
    EXPECT_NO_THROW(result = ctx.CalculateChecksum(fake_stream_in));

    EXPECT_EQ(Control, result);
}

TEST_F(CryptoGuardCtxTest, ShouldGetErrorIfInputFileEmpty) {
    std::stringstream fake_stream_in;

    char tmp;
    fake_stream_in >> tmp; /* Delete null terminator */

    std::string result;

    ASSERT_THROW(ctx.CalculateChecksum(fake_stream_in), CryptoGuardException);
    EXPECT_EQ(ctx.GetLastError(), CryptoGuardCtx::ERROR::EEMPTY_INPUT_FILE);
}
}  // namespace CryptoGuard
