#pragma once

struct EtherHdr {
    unsigned char dst[6]; // Destination MAC addrees 
    unsigned char src[6]; // source MAC address
    unsigned short type;  // EtherType
};

struct IPv4Hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl : 4;
    unsigned int version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version : 4;
    unsigned int ihl : 4;
#endif
    unsigned char  tos;
    unsigned short totLen;
    unsigned short id;
    unsigned short fragOff;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short check;
    unsigned int   saddr;
    unsigned int   daddr;
};

struct TcpHdr {
    unsigned short source;
    unsigned short dest;
    unsigned int seq;
    unsigned int ackSeq;
    unsigned char offsetReserved;
    unsigned char flags;
    unsigned short window;
    unsigned short check;
    unsigned short urgPtr;
};

struct UdpHdr {
    unsigned short source;
    unsigned short dest;
    unsigned short len;
    unsigned short check;
};

