#pragma once

struct EtherHdr {
    uint8_t dst[6]; // Destination MAC addrees 
    uint8_t src[6]; // source MAC address
    uint16_t type;  // EtherType
};

struct IPv4Hdr {
    uint8_t ihl_version;
    uint8_t  tos;
    uint16_t totLen;
    uint16_t id;
    uint16_t fragOff;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t   saddr;
    uint32_t daddr;
};

struct TcpHdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ackSeq;
    uint8_t offsetReserved;
    uint8_t flags;
    uint16_t window;
    uint16_t check;
    uint16_t urgPtr;
};

struct UdpHdr {
    unsigned short source;
    unsigned short dest;
    unsigned short len;
    unsigned short check;
};

