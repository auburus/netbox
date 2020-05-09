#ifndef NETBOX
#define NETBOX

#include <cstddef>
#include <cstdint>
#include <cassert>

namespace netbox
{

namespace ipv4
{

constexpr bool packet_meets_required_size(const uint16_t packet_len)
{
    return packet_len >= 20;
}

constexpr uint16_t makeUint16(const uint8_t byte_1, const uint8_t byte_0)
{
    union uint16 {
        uint8_t bytes[2];
        uint16_t data;
        constexpr uint16(uint8_t b1, uint8_t b0) : bytes{b0, b1} {}
    };
    uint16 tmp{byte_1, byte_0};
    return tmp.data;
}

class Packet
{
public:
    constexpr Packet(const uint8_t *ptr, const uint16_t len)
        : m_ptr(ptr), m_len(len)
    {
        assert(packet_meets_required_size(len));
    }

    constexpr uint8_t getVersion() const
    {
        return (*m_ptr & 0xF0) >> 4;
    }

    constexpr uint8_t getIHL() const
    {
        return (*m_ptr & 0x0F);
    }

    constexpr uint8_t getDSCP() const
    {
        return (*(m_ptr + 1) & 0xFA);
    }

    constexpr uint8_t getECN() const
    {
        return (*(m_ptr + 1) & 0x06);
    }

    constexpr uint16_t getTotalLength() const
    {
        return makeUint16(*(m_ptr + 2), *(m_ptr + 3));
    }

    constexpr uint16_t getIdentification() const
    {
        return makeUint16(*(m_ptr + 4), *(m_ptr + 5));
    }

    constexpr bool getFlagEvil() const
    {
        return *(m_ptr + 6) & 0x80;
    }

    constexpr bool getFlagDF() const
    {
        return *(m_ptr + 6) & 0x40;
    }

    constexpr bool getFlagMF() const
    {
        return *(m_ptr + 6) & 0x08;
    }

    constexpr uint16_t getFragmentOffset() const
    {
        return makeUint16(*(m_ptr + 6) & 0xE0, *(m_ptr + 7));
    }

    constexpr uint8_t getTTL() const
    {
        return *(m_ptr + 8);
    }

    constexpr uint8_t getProtocol() const
    {
        return *(m_ptr + 9);
    }

    constexpr uint16_t getHeaderChecksum() const
    {
        return makeUint16(*(m_ptr + 10), *(m_ptr + 11));
    }

    constexpr const uint8_t *getPayload() const
    {
        return m_ptr + getIHL() * 4;
    }

    constexpr uint16_t getPayloadLength() const
    {
        // The static cast is required due to integer promotion, because
        // of arithmetic operations
        return static_cast<uint16_t>(getTotalLength() - getIHL() * 4);
    }

    constexpr uint32_t getSourceIPAddress() const
    {
        union uint32 {
            uint16_t bitword16[2];
            uint32_t data;
            constexpr uint32(uint16_t b1, uint16_t b0) : bitword16{b0, b1} {}
        };
        uint32 temp = {makeUint16(*(m_ptr + 12), *(m_ptr + 13)),
                       makeUint16(*(m_ptr + 14), *(m_ptr + 15))};
        return temp.data;
    }

    constexpr uint32_t getDestinationAddress() const
    {
        union uint32 {
            uint16_t bitword16[2];
            uint32_t data;
            constexpr uint32(uint16_t b1, uint16_t b0) : bitword16{b0, b1} {}
        };
        uint32 temp = {makeUint16(*(m_ptr + 16), *(m_ptr + 17)),
                       makeUint16(*(m_ptr + 18), *(m_ptr + 19))};
        return temp.data;
    }

    constexpr uint16_t calculeChecksum() const
    {
        // Sum all the uint16_t header fields except for the checksum.
        // Add the carry to the final computation. Add it again if required
        // Finally, get the one's complement of the result

        union uint32 {
            uint16_t bitword16[2];
            uint32_t data;
            constexpr uint32() : data{0} {}
        };
        uint32 sum;

        for (auto i = 0; i < getIHL() * 4; i += 2)
        {
            sum.data += makeUint16(*(m_ptr + i), *(m_ptr + i + 1));
        }
        sum.data -= getHeaderChecksum();

        while (sum.bitword16[1] != 0)
        {
            sum.data = static_cast<uint32_t>(sum.bitword16[0]) + sum.bitword16[1];
        }

        return sum.bitword16[0] ^ 0xFFFF;
    }

    constexpr bool verifyChecksum() const
    {
        union uint32 {
            uint16_t bitword16[2];
            uint32_t data;
            constexpr uint32() : data{0} {}
        };
        uint32 sum;

        for (auto i = 0; i < getIHL() * 4; i += 2)
        {
            sum.data += makeUint16(*(m_ptr + i), *(m_ptr + i + 1));
        }

        while (sum.bitword16[1] != 0)
        {
            sum.data = static_cast<uint32_t>(sum.bitword16[0]) + sum.bitword16[1];
        }

        return sum.bitword16[0] == 0xFFFF;
    }

private:
    const uint8_t *m_ptr;
    uint16_t m_len;
};

} // namespace ipv4
} // namespace netbox

#endif