#pragma once

#include <pcap.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <WinSock2.h>
#include <ws2tcpip.h>

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
    std::string etherType;
public:
    EthernetHeader(const u_char* packet) : PacketHandlerBody(packet)
    {
        const EtherHdr* eth = reinterpret_cast<const EtherHdr*>(packet);

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

        ethrTypeFormatter(ntohs(eth->type));
        std::cout << "Ethernet header type: " << etherType << '\n';
    }

    void ethrTypeFormatter(uint16_t type)
    {
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
    }

    ~EthernetHeader() {}
};

class IpHeader : public EthernetHeader
{
public:
    IpHeader(const u_char* packet) : EthernetHeader(packet)
    {
        const IPv4Hdr* ip = reinterpret_cast<const IPv4Hdr*>(packet + sizeof(EtherHdr));
        uint8_t version = ip->versionIhl >> 4;
        uint8_t ihl = ip->versionIhl & 0x0F;

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
};

class TCP : public IpHeader
{

};

class UDP : public IpHeader
{

};

class Payload : public PacketHandlerBody
{

};

class Offsets : public PacketHandlerBody
{

};