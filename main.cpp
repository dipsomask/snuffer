#include <iostream>
#include <string.h>
#include <vector>

#include <pcap.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

using std::cout;
using std::endl;
using str = std::string;


void PacketHeader(unsigned char* char_, const struct pcap_pkthdr *header, const u_char *packet){

    struct ip* ipheader = (struct ip*)(packet + 14); // +14 байт на ip заголовок

    char source_ip[INET_ADDRSTRLEN];
    char destination_ip[INET_ADDRSTRLEN];
    str source_port = "nan";
    str destination_port = "nan";
    str protocol_t;

    inet_ntop(AF_INET, &ipheader->ip_src, source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ipheader->ip_dst, destination_ip, INET_ADDRSTRLEN);

    switch (ipheader->ip_p)
    {
    case IPPROTO_TCP:{
        protocol_t = "TCP";
        
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct ip)); // +28 байт на ip и ethhdr заголовок
        
        source_port = std::to_string(ntohs(tcp_header->source));
        destination_port = std::to_string(ntohs(tcp_header->dest));
        break;
    }
       
    case IPPROTO_UDP:{
        protocol_t = "UDP";
        
        struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct ip)); // +28 байт на ip и ethhdr заголовок
        
        source_port = std::to_string(ntohs(udp_header->source));
        destination_port = std::to_string(ntohs(udp_header->dest));
        break;
    }
    
    default:
        return;
    }

    cout << protocol_t << "\t" << source_ip << ":" << source_port << "\t" << destination_ip << ":" << destination_port << "\t" << ipheader->ip_len << endl;

}



int main(int argc, char* argv[]){

    char err_mess[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    if(pcap_findalldevs(&alldevs, err_mess) == -1){
        cout << "\nОшибка по функции 'pcap_findalldevs': " + (str)err_mess + "\n" << endl;
        return -1;
    }

    pcap_t* live_of_devise = pcap_open_live(alldevs->name, BUFSIZ, 1, 500, err_mess);

    pcap_loop(live_of_devise, -1, PacketHeader, nullptr);

    pcap_close(live_of_devise);

    pcap_freealldevs(alldevs);


    return 0;
}
