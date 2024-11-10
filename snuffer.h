#include <iostream>
#include <pcap.h>
#include <vector>

using namespace std;
using str = string;


/*class Snuffer{

private:
    pcap_if_t* devises = nullptr;
    unsigned int countd = 0;

    friend void PacketHeader(unsigned char* char_, const struct pcap_pkthdr *header, const u_char *packet);
    friend void CatchPacketsInThread(pcap_t* live_of_devise, str name);

public:
    explicit Snuffer();
    ~Snuffer(){};
    unsigned int getDevsCount() const;
    virtual int SendInfo() final;

};*/

class Devise{

private:
    pcap_if_t* devise = nullptr;
    pcap_t* live_of_devise = nullptr;

    friend void PacketHeader(unsigned char* char_, const struct pcap_pkthdr *header, const u_char *packet);

public:
    Devise(pcap_if_t* dev);
    ~Devise(){};
    pcap_t* GetLiveOfDevise();
    pcap_if_t* GetDevise();
    void SendInfo();

};


class DevisesStorage{

private:
    pcap_if_t* deviceAtTheMoment;
    vector<Devise> devices;

public:
    explicit DevisesStorage();
    ~DevisesStorage(){};
    void SnufferProcess();
    vector<Devise>& GetVectorDevs();
};