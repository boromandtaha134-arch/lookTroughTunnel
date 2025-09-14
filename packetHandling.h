#pragma once

#include <pcap.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <thread>

#include "packetLayerData.h"

#define IPv4 0x0800
#define ARP 0x0806
#define WakeOnLAN 0x0842
#define RARP 0x8035
#define VLAN 0x8100
#define IPX 0x8137
#define IPv6 0x86DD
#define PPPoEDiscovery 0x8863
#define PPPoESession 0x8864
#define EAPoL 0x888E
#define PROFINET 0x8892
#define HyperSCSI 0x889A
#define MPLSUnicast 0x8847
#define MPLSMulticast 0x8848

extern int modeStatus;

void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);
std::string& macFormatter(const uint8_t* macAddress);

class PacketHandlerBody
{
private:
    const u_char* packet;
public:
    PacketHandlerBody()
    {
        throw std::invalid_argument("No packet received");// init parent firts
    }
    PacketHandlerBody(const u_char* packet) : packet(packet) {}

    ~PacketHandlerBody() {};
};

class EthernetHeader : public PacketHandlerBody
{
private:
    const EtherHdr* eth;
public:
    EthernetHeader(const u_char* packet) : PacketHandlerBody(packet)
    {
        eth = reinterpret_cast<const EtherHdr*>(packet);
    }

    const EtherHdr* ethGetter() { return eth; }

    void ethernetHeaderInfo()
    {

        uint8_t sourceData[6] = {
            eth->src[0],  eth->src[1], eth->src[2],
            eth->src[3],  eth->src[4], eth->src[5]
        };

        uint8_t destinationData[] = {
            eth->dst[0],  eth->dst[1], eth->dst[2],
            eth->dst[3],  eth->dst[4], eth->dst[5]
        };

        std::string& formattedSource = macFormatter(sourceData);
        std::string& formattedDestination = macFormatter(destinationData);

        std::cout << "Source MAC:      " << formattedSource << '\n';
        std::cout << "Destination MAC: " << formattedDestination << '\n';
        std::cout << "Ethernet header type: " << ethrTypeFormatter(ntohs(eth->type)) << '\n';
    }

    std::string ethrTypeFormatter(uint16_t type)
    {
        std::string etherType;
        switch (type)
        {
        case IPv4:
            etherType = "IPv4";
            break;
        case ARP:
            etherType = "ARP";
            break;
        case WakeOnLAN:
            etherType = "WakeOnLAN";
            break;
        case RARP:
            etherType = "RARP";
            break;
        case VLAN:
            etherType = "VLAN";
            break;
        case IPX:
            etherType = "IPX";
            break;
        case IPv6:
            etherType = "IPv6";
            break;
        case PPPoEDiscovery:
            etherType = "PPPoEDiscovery";
            break;
        case PPPoESession:
            etherType = "PPPoESession";
            break;
        case EAPoL:
            etherType = "EAPoL";
            break;
        case PROFINET:
            etherType = "PROFINET";
            break;
        case HyperSCSI:
            etherType = "HyperSCSI";
            break;
        case MPLSUnicast:
            etherType = "MPLSUnicast";
            break;
        case MPLSMulticast:
            etherType = "MPLSMulticast";
            break;
        default:
            etherType = "Unknown";
            break;
        }
        return etherType;
    }

    ~EthernetHeader() {}
};

class IpHeader : public EthernetHeader
{
private:
    const IPv4Hdr* ip;
    bool IPv4Flag;
    bool TCPFlag;
public:
    IpHeader(const u_char* packet) : EthernetHeader(packet)
    {
        IPv4Flag = false;
        TCPFlag = false;

        ip = reinterpret_cast<const IPv4Hdr*>(packet + sizeof(EtherHdr));
        if ((int)ip->protocol == 6)
        {
            TCPFlag = true;
        }
        else if ((int)ip->protocol == 17)
        {
            TCPFlag = false;
        }
        else
        {
            std::cout << "Unsupported protocol!\n";
        }
    }

    void IPv4HeaderInfo()
    {
        if (ntohs(ethGetter()->type) == IPv4)
        {
            IPv4Flag = true;

            uint8_t version = ip->ihl_version >> 4;
            uint8_t ihl = ip->ihl_version & 0x0F;
            
            std::cout << "Version: " << (int)version << "\n";
            std::cout << "IHL: " << (int)ihl * 4 << " bytes\n";
            std::cout << "Protocol: " << (int)ip->protocol << "\n";
            std::cout << "Source IP: " << ((ip->saddr >> 24) & 0xFF) << "."
                << ((ip->saddr >> 16) & 0xFF) << "."
                << ((ip->saddr >> 8) & 0xFF) << "."
                << (ip->saddr & 0xFF) << "\n";
            std::cout << "Destination IP: " << ((ip->daddr >> 24) & 0xFF) << "."
                << ((ip->daddr >> 16) & 0xFF) << "."
                << ((ip->daddr >> 8) & 0xFF) << "."
                << (ip->daddr & 0xFF) << "\n";
        }
        else
        {
            IPv4Flag = false;
            std::cout << "unsoppurted ip version\n";
        }
    }

    inline bool IPv4FlagGetter() { return IPv4Flag; }
    inline bool TCPFlagGetter() { return TCPFlag; }
};

class TCPHandler : public IpHeader
{
private:
    const TcpHdr* tcp;
public:
    TCPHandler(const u_char* packet) : IpHeader(packet)
    {
            tcp = reinterpret_cast<const TcpHdr*>(packet + (sizeof(EtherHdr) + sizeof(IPv4Hdr)));
    }

    void TCPHeaderInfo()
    {
        std::cout << "Source port is: " << tcp->source << '\n';
        std::cout << "Destination port is: " << tcp->dest << '\n';
        std::cout << "Sequence number is: " << tcp->seq << '\n';
        bool flags[8] = { flag() };
        if (flags[5])
        {
            std::cout << "ACK sequence number is: " << tcp->ackSeq << '\n';
        }
        std::cout << "Header length is: " << (tcp->offsetReserved & 0xF0) << '\n';
        std::cout << "Reserved is: " << (tcp->offsetReserved & 0x8F) << '\n';
        std::cout << "nsFlag is: " << (tcp->offsetReserved & 0x7F) << '\n';
    }

    bool flag()
    {
        uint8_t flags = tcp->flags;
        bool checkedFlags[8] = {
            flags & 0x01,//FIN
            flags & 0x02,//SYN
            flags & 0x04,//RST
            flags & 0x08,//PSH
            flags & 0x10,//ACK
            flags & 0x20,//URG
            flags & 0x40,//ECE
            flags & 0x80 //CWR
        };

        std::cout << "FIN: " << checkedFlags[0] << '\n';
        std::cout << "SYN: " << checkedFlags[1] << '\n';
        std::cout << "RST: " << checkedFlags[2] << '\n';
        std::cout << "PSH: " << checkedFlags[3] << '\n';
        std::cout << "ACK: " << checkedFlags[4] << '\n';
        std::cout << "URG: " << checkedFlags[5] << '\n';
        std::cout << "ECE: " << checkedFlags[6] << '\n';
        std::cout << "CWR: " << checkedFlags[7] << '\n';

        return checkedFlags;
    }
};

class UDPHandler : public IpHeader
{

};

class Payload : public TCPHandler 
{
private:
    const u_char* packet;
public:
    Payload(const u_char* packet) : TCPHandler(packet)
    {
        this->packet = packet;
        
    }

    void payloadHandler(int headerLen) 
    {
        const u_char* payload = packet + sizeof(EtherHdr) + sizeof(IPv4Hdr) + sizeof(TcpHdr);
        int payload_len = headerLen - (sizeof(EtherHdr) + sizeof(IPv4Hdr) + sizeof(TcpHdr));

        if (payload_len > 0) 
        {
            std::string payload_str((char*)payload, payload_len);
            std::cout << "Captured Payload: " << payload_str.substr(0, 200) << '\n';
        }
    }
};