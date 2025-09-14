#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <thread>
#include <mutex>
#include <string>

namespace Proxy {

    std::mutex cout_mutex;
    std::atomic<bool> proxyRunning(true);

    inline void log(const std::string& msg) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "[PROXY LOG] " << msg << std::endl;
    }

    inline void handle_proxy(int clientSock) {
        log("Handling new client connection");
        int serverSock = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSock == INVALID_SOCKET) {
            log("Server socket creation failed: " + std::to_string(WSAGetLastError()));
            closesocket(clientSock);
            return;
        }

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(80);
        inet_pton(AF_INET, "93.184.216.34", &serverAddr.sin_addr); // IP example.com

        if (connect(serverSock, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            log("Connection to server failed: " + std::to_string(WSAGetLastError()));
            closesocket(clientSock);
            closesocket(serverSock);
            return;
        }

        char buffer[4096];
        while (proxyRunning) {
            int bytes = recv(clientSock, buffer, sizeof(buffer), 0);
            if (bytes <= 0) break;

            std::string data(buffer, bytes);
            if (data.find("GET") != std::string::npos) {
                log("HTTP Request: " + data.substr(0, 100));
                data += "\r\nX-Modified: lookTroughTunnel\r\n";
            }

            send(serverSock, data.c_str(), data.size(), 0);
            bytes = recv(serverSock, buffer, sizeof(buffer), 0);
            if (bytes <= 0) break;
            send(clientSock, buffer, bytes, 0);
        }

        closesocket(clientSock);
        closesocket(serverSock);
        log("Client connection closed");
    }

    inline void proxyThreadFunc(int listenSock) {
        log("Starting proxy thread");
        while (proxyRunning) {
            int clientSock = accept(listenSock, nullptr, nullptr);
            if (clientSock == INVALID_SOCKET) {
                log("Accept failed: " + std::to_string(WSAGetLastError()));
                if (!proxyRunning) break;
                continue;
            }
            std::thread(handle_proxy, clientSock).detach();
        }
    }

    inline int startProxy() {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            log("WSAStartup failed: " + std::to_string(WSAGetLastError()));
            return -1;
        }

        int listenSock = socket(AF_INET, SOCK_STREAM, 0);
        if (listenSock == INVALID_SOCKET) {
            log("Socket creation failed: " + std::to_string(WSAGetLastError()));
            WSACleanup();
            return -1;
        }

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(8080);
        addr.sin_addr.s_addr = INADDR_ANY;

        int opt = 1;
        setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

        if (bind(listenSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            log("Bind failed: " + std::to_string(WSAGetLastError()));
            closesocket(listenSock);
            WSACleanup();
            return -1;
        }

        if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
            log("Listen failed: " + std::to_string(WSAGetLastError()));
            closesocket(listenSock);
            WSACleanup();
            return -1;
        }
        log("Proxy listening on port 8080");

        system("netsh interface portproxy add v4tov4 listenport=80 listenaddress=0.0.0.0 connectport=8080 connectaddress=127.0.0.1");

        proxyRunning = true;
        std::thread proxyThread(proxyThreadFunc, listenSock);
        proxyThread.detach();

        return listenSock; 
    }

    inline void stopProxy(int listenSock) {
        log("Stopping proxy");
        proxyRunning = true;
        closesocket(listenSock);
        system("netsh interface portproxy delete v4tov4 listenport=80 listenaddress=0.0.0.0");
        WSACleanup();
    }

}

