#include "netbox.hpp"

#include <array>
#include <gtest/gtest.h>

namespace netbox_test
{

using namespace netbox;

TEST(ExampleTest, Dummy)
{
    // clang-format off
    constexpr std::array<uint8_t, 20> emptyIpv4 = {
        0x45, 0x00, 0x00, 0x14,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x00, 0x7c, 0xe7,
        0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01
    };
    // clang-format on

    ASSERT_TRUE(ipv4::packet_meets_required_size(emptyIpv4.size()));

    ipv4::Packet packet{emptyIpv4.data(), emptyIpv4.size()};

    ASSERT_EQ(packet.getVersion(), 4);
    ASSERT_EQ(packet.getIHL(), 5);
    ASSERT_EQ(packet.getDSCP(), 0);
    ASSERT_EQ(packet.getECN(), 0);
    ASSERT_EQ(packet.getTotalLength(), 20);
    ASSERT_EQ(packet.getIdentification(), 1);
    ASSERT_EQ(packet.getFlagEvil(), false);
    ASSERT_EQ(packet.getFlagDF(), false);
    ASSERT_EQ(packet.getFlagMF(), false);
    ASSERT_EQ(packet.getFragmentOffset(), 0);
    ASSERT_EQ(packet.getTTL(), 64);
    ASSERT_EQ(packet.getProtocol(), 0);
    ASSERT_EQ(packet.getHeaderChecksum(), packet.calculeChecksum());
    ASSERT_TRUE(packet.verifyChecksum());
    ASSERT_EQ(packet.getSourceIPAddress(), (127 << 24) + 1);
    ASSERT_EQ(packet.getDestinationAddress(), (127 << 24) + 1);
    ASSERT_EQ(packet.getPayload(), &emptyIpv4.back() + 1);
    ASSERT_EQ(packet.getPayloadLength(), 0);
}

} // namespace netbox_test