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
        if(tcpHandler.TCPFlagGetter())
        {
            tcpHandler.TCPHeaderInfo();
        }
        else
        {
            std::cout << "Non TCP porotocol, TCP handling failed.\n";
        }
    }
    else if (modeStatus == 4)
    {
        Payload payload(receivedPacket);
        payload.ethernetHeaderInfo();
        payload.IPv4HeaderInfo();
        if(payload.IPv4FlagGetter() && payload.TCPFlagGetter())
        {
            payload.TCPHeaderInfo();
            payload.payloadHandler(header->len);
        }
        else
        {
            std::cout << "Payload sniffing only is available on TCP/IPv4 packets.\n";
        }
        
    }
    else
    {
        std::cout << "please enter a vaild number.\n";
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