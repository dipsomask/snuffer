#include <iostream>
#include <string.h>

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include "sniffer.h"


using str = std::string;
using std::cout;
using std::endl;
using std::to_string;


int main() {
    
    try
    {
        Sniffer sf;

        sf.StartSnifferProcess();

    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << "\n";
    }
    

    return 0;
}
