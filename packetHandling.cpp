#include "packetHandling.h"

int modeStatus;

void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* receivedPacket)
{
    if (modeStatus == 1)
    {
        EthernetHeader etherHdr(receivedPacket);
    }
    else if (modeStatus == 2)
    {
        ;
    }
    else if (modeStatus == 3)
    {
        ;
    }
    else if (modeStatus == 4)
    {
        ;
    }
    else
    {
        ;
    }
    
}

std::string etherTypeConversion(u_short& type) 
{
    static const std::unordered_map<u_int, std::string> etherTypes{
        {0x0800, "IPv4"},
        {0x0806, "ARP"},
        {0x0842, "WakeOnLAN"},
        {0x8035, "RARP"},
        {0x8100, "VLAN"},
        {0x8137, "IPX"},
        {0x86DD, "IPv6"},
        {0x8863, "PPPoEDiscovery"},
        {0x8864, "PPPoESession"},
        {0x888E, "EAPoL"},
        {0x8892, "PROFINET"},
        {0x889A, "HyperSCSI"},
        {0x8847, "MPLSUnicast"},
        {0x8848, "MPLSMulticast"}
    };

    auto convertedType = etherTypes.find(type);
    if (convertedType != etherTypes.end())
        return convertedType->second;
    return "Unknown";
}