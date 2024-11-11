#include <iostream>
#include <pcap.h>

class Sniffer{
    
private:
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevices;
    pcap_t* handle;

    friend void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet); 

public:
    Sniffer();
    ~Sniffer();
    virtual void StartSnifferProcess();
    virtual int StopSnifferProcess();
    pcap_if_t* GetDeviceListHead() const;
    pcap_t* GetHandle() const;


};
