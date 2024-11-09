#include <iostream>
#include <pcap.h>

using namespace std;
using str = string;


class Snuffer{

private:
    pcap_if_t* devises = nullptr;
    unsigned int countd = 0;

    friend void PacketHeader(unsigned char* char_, const struct pcap_pkthdr *header, const u_char *packet);
    friend void CatchPacketsInThread(pcap_t* live_of_devise, str& name);

public:
    explicit Snuffer();
    unsigned int getDevsCount() const;
    virtual int SendInfo() final;

};