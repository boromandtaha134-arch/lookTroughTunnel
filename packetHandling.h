#pragma once

#include <pcap.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <WinSock2.h>
#include <ws2tcpip.h>

#include "packetLayerData.h"

#define INTERNAL_USAGE_MODE 0
#define USER_USAGE_MODE 1

extern int modeStatus;

void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);
std::string& macFormatter(const uint8_t* macAddress);
std::string etherTypeConversion(const u_short type);

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

    const u_char* packetGetter() const
    {
        return packet;
    }

    ~PacketHandlerBody() {};
};

class EthernetHeader : public PacketHandlerBody
{
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
        std::cout << "Ethernet header type: " << etherTypeConversion(ntohs(eth->type)) << '\n';
    }

    ~EthernetHeader() {}
};

class IpHeader : public PacketHandlerBody
{
public:
    IpHeader(const u_char* packet) : PacketHandlerBody(packet)
    {
        const IpHdr* ip = reinterpret_cast<const IpHdr*>(packet + 14);
        uint8_t version = ip->version >> 4;
        uint8_t ihl = ip->ihl & 0x0F;

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