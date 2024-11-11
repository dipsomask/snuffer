#include <iostream>
#include "sniffer.h"

#include <string.h>

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

using namespace std;

using str = std::string;
using std::cout;
using std::endl;
using std::to_string;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    str return_;
    str source_ip;
    str destination_ip;
    str source_port{"INF"};
    str destination_port{"INF"};
    str protocol_type;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        source_ip = (str)inet_ntoa(ip_header->ip_src);
        destination_ip = (str)inet_ntoa(ip_header->ip_dst);

        if(source_ip == destination_ip){
            return;
        }

        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            source_port = to_string(ntohs(tcp_header->source));
            destination_port = to_string(ntohs(tcp_header->dest));
            protocol_type = "TCP";
        }

        else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            source_port = to_string(ntohs(udp_header->source));
            destination_port = to_string(ntohs(udp_header->dest));
            protocol_type = "UDP";
        }

        else if (ip_header->ip_p == IPPROTO_ICMP) {
            protocol_type = "ICMP";
        }

        return_ = source_ip + " " + destination_ip + " " + protocol_type + " " + source_port + " " + destination_port;
        
    }

    if(!return_.empty()){
        cout << return_ << endl;
    }

}


Sniffer::Sniffer(){

    if (pcap_findalldevs(&alldevices, error_buffer) == -1) {
        throw std::logic_error("Ошибка поиска интерфейсов: " + (str)error_buffer);
    }

    handle = pcap_open_live(alldevices->name, BUFSIZ, 1, 1000, error_buffer);
    
    if (handle == nullptr) {
        throw std::logic_error("Ошибка открытия интерфейсов: " + (str)error_buffer);
    }

}

Sniffer::~Sniffer(){

    pcap_close(handle);
    pcap_freealldevs(alldevices);

}

void Sniffer::StartSnifferProcess(){

    cout << endl << alldevices->name << endl;

    pcap_loop(handle, 0, packet_handler, nullptr);

}

int Sniffer::StopSnifferProcess(){

    if(handle == nullptr){
        return -1;
    }
    else{
        pcap_breakloop(handle);
        return 0;
    }

}

pcap_if_t* Sniffer::GetDeviceListHead() const{
    
    return alldevices;

}

pcap_t* Sniffer::GetHandle() const{

    return handle;

}