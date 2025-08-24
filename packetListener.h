#pragma once

#include <pcap.h>
#include <vector>

class Listener
{
private:
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* alldevs;
	pcap_if_t* device;
	std::vector <pcap_if_t*> devices;
public:
	Listener();
	~Listener();

	inline char* errbufGetter();

	std::vector<pcap_if_t*> deviceInit();
	pcap_if_t* devicePicker();
	pcap_t* handelInit(pcap_if_t* device, int pocketSize, bool promisc, int time);
};
