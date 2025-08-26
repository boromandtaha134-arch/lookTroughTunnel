#pragma once

#include <pcap.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include "IPtypes.h"

extern int modeStatus;

void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);
std::string etherTypeConversion(u_short& type);

class PacketHandlerBody
{
private:
    const u_char* packet;
public:
    PacketHandlerBody()
    {
        throw std::invalid_argument("No packet received");
        // init parent firts
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
        EtherHdr* eth = (EtherHdr*)packetGetter();
        std::cout << "Source MAC:      \n" << 
            eth->src[0] << eth->src[1] << eth->src[2] <<
            eth->src[3] << eth->src[4] << eth->src[5];
        std::cout << "Destination MAC: \n" <<
            eth->dst[0] << eth->dst[1] << eth->dst[2] <<
            eth->dst[3] << eth->dst[4] << eth->dst[5];
        std::cout << "Ethernet header type: " << etherTypeConversion(eth->type) << '\n';
    }

    ~EthernetHeader() {}
};

class IpHeader : public PacketHandlerBody
{

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