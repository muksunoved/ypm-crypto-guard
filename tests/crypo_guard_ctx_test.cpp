#include "crypto_guard_ctx.h"
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
    std::string fake_content_in;
    std::string fake_content_out;
    std::stringstream fake_stream_in(fake_content_in);
    std::stringstream fake_stream_out(fake_content_out);
    std::string password("12345");
    char tmp;
    fake_stream_in >> tmp; /* Delete null terminator */

    EXPECT_THROW(ctx.EncryptFile(fake_stream_in, fake_stream_out, password), CryptoGuardCtx::CryptoGuardException);
    EXPECT_EQ(ctx.GetLastError(), CryptoGuardCtx::ERROR::EEMPTY_INPUT_FILE);
}

}  // namespace CryptoGuard
