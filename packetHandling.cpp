#include <iomanip>
#include <sstream>

#include "packetHandling.h"

int modeStatus;

void proxyProccess(int clientSock) {
    // connect to server
    int serverSock = socket(AF_INET, SOCK_STREAM, 0);//open a IPv4 and TCP socket 
    sockaddr_in server_addr; // store ipv4 and port info
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(80);
    inet_pton(AF_INET, "93.184.216.34", &server_addr.sin_addr); // IP example.com

    if (connect(serverSock, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cout << "Connection to server failed\n";
        closesocket(clientSock);
        closesocket(serverSock);
        return;
    }

    char buffer[4096];

    u_long mode = 1;
    ioctlsocket(clientSock, FIONBIO, &mode);
    ioctlsocket(serverSock, FIONBIO, &mode);

    while (true) {
        // read from client
        int bytes = recv(clientSock, buffer, sizeof(buffer), 0);
        if (bytes <= 0)
        {
            break;
        }
        // payload manipulation
        std::string data(buffer, bytes);
        if (data.find("GET") != std::string::npos) {
            std::cout << "HTTP Request: " << data << std::endl;
            data += "\r\nX-Modified: lookTroughTunnel\r\n"; // add header
        }
        else if (bytes == 0)
        {
            std::cout << "Client disconnected\n";
            break;
        }
        else
        {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                std::cerr << "recv(client) error: " << err << '\n';
                break;
            }
        }

        // send to server
        send(serverSock, data.c_str(), data.size(), 0);

        // read form server send to client
        bytes = recv(serverSock, buffer, sizeof(buffer), 0);
        if (bytes <= 0)
        {
            break;
        }
        send(clientSock, buffer, bytes, 0);

        if (bytes == 0) {
            std::cout << "Server disconnected\n";
            break;
        }
        else 
        {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                std::cerr << "recv(server) error: " << err << '\n';
                break;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    closesocket(clientSock);
    closesocket(serverSock);
}

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
        Payload payload(receivedPacket);
        payload.ethernetHeaderInfo();
        payload.IPv4HeaderInfo();
        #ifdef TCP
        payload.TCPHeaderInfo();
        payload.payloadHandler(header->len);
        #endif
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