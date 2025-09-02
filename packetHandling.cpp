#include <iomanip>
#include <sstream>

#include "packetHandling.h"

int modeStatus;

void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* receivedPacket)
{
    if (modeStatus == 1)
    {
        EthernetHeader etherHdr(receivedPacket);
        etherHdr.ethernetHeaderInfo();
    }
    else if (modeStatus == 2)
    {
        IpHeader ipHdr(receivedPacket);
        ipHdr.ethernetHeaderInfo();
        ipHdr.IPv4HeaderInfo();
    }
    else if (modeStatus == 3)
    {
        TCPHandler tcpHandler(receivedPacket);
        tcpHandler.ethernetHeaderInfo();
        tcpHandler.IPv4HeaderInfo();
        #ifdef TCP
        tcpHandler.TCPHeaderInfo();
        #endif
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

std::string& macFormatter(const uint8_t* macAddress)
{
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i)
    {
        if (i != 0)
        {
            oss << ':'; 
        }
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(macAddress[i]);
    }

    static std::string resault = oss.str();
    return resault;
}