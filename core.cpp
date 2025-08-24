// a stream of trafic of apps

#include <pcap.h>

#include <iostream>
#include <vector>
#include <thread>
#include <atomic>

#include "packetListener.h"


void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) 
{
    std::cout << "Got a packet! Length: " << header->len << " bytes" << '\n';
}

void collectingLoop(pcap_t* handle) 
{
    if (pcap_loop(handle, 0, packetHandler, nullptr) == -1) {
        std::cerr << "Error in pcap_loop\n";
    }
}

int main() 
{
    Listener listener;
    std::vector<pcap_if_t*> devices = listener.deviceInit();
    pcap_if_t* currentDevice = listener.devicePicker();

    std::cout << "Using device: " << currentDevice->name << '\n';

    pcap_t* handle = listener.handelInit(currentDevice, 65536, 1, 1000);

    std::cout << "Listening for packets... Press Ctrl+C to stop.\n" << "press < c > to change device or press < q > to quiet\n";

    std::atomic<bool> running(true);
    std::thread t(collectingLoop, handle);

    while (running)
    {
        char changingStatus;
        std::cin >> changingStatus;
        if ((changingStatus == 'c') || (changingStatus == 'C'))
        {
            pcap_breakloop(handle);
            t.join();
            pcap_close(handle);

            currentDevice = listener.devicePicker();
            handle = listener.handelInit(currentDevice, 65536, 1, 500);

            t = std::thread(collectingLoop, handle);
            std::cout << "Listening for packets... Press Ctrl+C to stop.\n" << "press < c > to change device or press < q > to quiet\n";
        }
        else if ((changingStatus == 'q') || (changingStatus == 'Q'))
        {
            running = false;
            pcap_breakloop(handle);
        }
    }

    t.join();
    pcap_close(handle);
    
    return 0;
}

