#pragma once

struct EtherHdr {
    unsigned char dst[6]; // Destination MAC addrees 
    unsigned char src[6]; // source MAC address
    unsigned short type;  // EtherType
};

struct IPv4Hdr {
    uint8_t versionIhl;
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

/*struct IPv6Hdr {

};and other versions will add*/

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

