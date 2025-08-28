// a stream of trafic of apps

#include <thread>
#include <atomic>
#include <ctime>
#include <mutex>
#include <condition_variable>

#include "packetListener.h"
#include "packetHandling.h"

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

    std::cout << "press < c > to change device or < m > to manage listening mode and press < q > to quiet\n";

    std::cout << "[1]MAC address.\n[2]IP header.\n[3]Detecting protocol(TCP/UDP).\n[4]Payload.\n[5]Offset.\n";
    std::cin >> modeStatus;

    std::atomic<bool> running(true);
    std::thread t(collectingLoop, handle);

    while (running)
    {
        char choise;
        std::cin >> choise;

        if ((choise == 'c') || (choise == 'C'))
        {
            pcap_breakloop(handle);
            t.join();
            pcap_close(handle);

            currentDevice = listener.devicePicker();
            handle = listener.handelInit(currentDevice, 65536, 1, 500);

            t = std::thread(collectingLoop, handle);
            std::cout << "press < c > to change device or < m > to change listening mode and press < q > to quiet\n";
            std::cout << "[1]MAC address.\n[2]IP header.\n[3]Detecting protocol(TCP/UDP).\n[4]Payload.\n[5]Offset.\n";
            std::cin >> modeStatus;
        }
        else if ((choise == 'm') || (choise == 'M'))
        {
            std::cout << "[1]MAC address.\n[2]IP header.\n[3]Detecting protocol(TCP/UDP).\n[4]Payload.\n[5]Offset.\n";
            std::cin >> modeStatus;
        }
        else if ((choise == 'q') || (choise == 'Q'))
        {
            running = false;
            pcap_breakloop(handle);
        }
    }

    t.join();
    pcap_close(handle);
    
    return 0;
}
