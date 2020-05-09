#ifndef TEST_HELPERS
#define TEST_HELPERS

#include <gtest/gtest.h>

namespace netbox_test
{

TEST(ExampleTest, Dummy)
{
    int a = 1;
    int b = 3;
    ASSERT_EQ(2 * a, b);
}

} // namespace netbox_test

#endif