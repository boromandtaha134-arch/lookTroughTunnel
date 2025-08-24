#include "packetListener.h"

#include <iostream>

Listener::Listener()
{
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
    }

    device = alldevs;

    if (!device) {
        std::cerr << "No devices found!" << std::endl;
    }
}

Listener::~Listener() 
{
    pcap_freealldevs(alldevs);
}

inline char* Listener::errbufGetter() { return errbuf; }

std::vector<pcap_if_t*> Listener::deviceInit()
{
    for (; device != nullptr; device = device->next)
    {
        if (device)
        {
            devices.push_back(device);
        }
    }
    return devices;
}

pcap_if_t* Listener::devicePicker() 
{
    std::cout << "devices list:\n";
    int counter = 0;
    for (pcap_if_t* device : devices)
    {
        ++counter;
        std::cout << "\t" << counter << ')' << device->name << '\n';

    }

    std::cout << "choose device by device number: ";
    int pickedDevice;
    std::cin >> pickedDevice;
    return devices[pickedDevice];
}

pcap_t* Listener::handelInit(pcap_if_t* device,int pocketSize, bool promisc, int time) 
{
    pcap_t* handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
    }

    return handle;
}