#include <iostream>
#include <thread>
#include <string.h>
#include <vector>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <chrono>

#include "snuffer.h"


using namespace std;
using str = string;



void waiter(const int time, bool& finish){
    std::this_thread::sleep_for(std::chrono::seconds(time));
    finish = true;
}


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
        protocol_t = "nan";
        break;
    }

    cout << protocol_t << "\t" << source_ip << ":" << source_port << "\t" << destination_ip << ":" << destination_port << "\t" << ipheader->ip_len << endl;

}

Devise::Devise(pcap_if_t* dev){
    devise = dev;

    char err_mess[PCAP_ERRBUF_SIZE];

    pcap_t* live_of_devise = pcap_open_live(devise->name, BUFSIZ, 1, 500, err_mess);
    if(live_of_devise == nullptr){
        cout << "\nНе получилось открыть девайс '" << devise->name << "', ошибка: " << (str)err_mess << "\n\n";
    }

}

pcap_t* Devise::GetLiveOfDevise(){
    return live_of_devise;
}

pcap_if_t* Devise::GetDevise(){
    return devise;
}

void Devise::SendInfo(){

    bool finish = false;
    thread wait(waiter, 5, ref(finish));

    pcap_loop(live_of_devise, 0, PacketHeader, nullptr);


    if (!finish) {
        pcap_breakloop(live_of_devise);
    }

    wait.join();
    pcap_close(live_of_devise);

}


DevisesStorage::DevisesStorage(){

    char err_mess[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&deviceAtTheMoment, err_mess) == -1){
        throw length_error("\nОшибка по функции 'pcap_findalldevs': " + (str)err_mess + "\n");
    }

}

void DevisesStorage::SnufferProcess(){

    vector<thread> threads;

    pcap_if_t* dev = deviceAtTheMoment;
    while(dev != nullptr){
        devices.emplace_back(dev);
        if(devices.back().GetLiveOfDevise() != nullptr){
            threads.push_back(thread(&Devise::SendInfo, &devices.back())); 
        }
        dev = dev->next;
    }

    for (auto& t : threads) {
        t.join();
    }

    pcap_freealldevs(deviceAtTheMoment);

}

vector<Devise>& DevisesStorage::GetVectorDevs(){
    return devices;
}


/*
void CatchPacketsInThread(pcap_t* live_of_devise, str name){

    bool finish = false;
    thread wait(waiter, 3, ref(finish));

    pcap_loop(live_of_devise, 10, PacketHeader, nullptr);

    cout << name << "--" << endl << "--------------------" << endl;

    if (!finish) {
        pcap_breakloop(live_of_devise);
    }

    wait.join();
    pcap_close(live_of_devise);

}


Snuffer::Snuffer(){
    
    char err_mess[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&devises, err_mess) == -1){
        throw length_error("\nОшибка по функции 'pcap_findalldevs': " + (str)err_mess + "\n");
    }

    pcap_if_t* save_pointer_of_first_devise = devises;
    unsigned int countd_ = 0;
    while(devises->next != nullptr){
        countd_++;
        devises = devises->next;
    }
    countd = countd_;
    devises = save_pointer_of_first_devise;

}


unsigned int Snuffer::getDevsCount() const{
    
    return countd;

}


int Snuffer::SendInfo(){
    
    char err_mess[PCAP_ERRBUF_SIZE];
    vector<thread> treads;

    pcap_if_t* save_pointer_of_first_devise = devises;
    
    while(devises != nullptr){
        pcap_t* live_of_devise = pcap_open_live(devises->name, BUFSIZ, 1, 500, err_mess);
        if(live_of_devise == nullptr){
            cout << "\nНе получилось открыть девайс '" << devises->name << "', ошибка: " << (str)err_mess << "\n\n";
            devises = devises->next;
            continue;
        }
        str name = devises->name;
        treads.push_back(thread(CatchPacketsInThread, live_of_devise, ref(name)));

        devises = devises->next;
    }

    //devises = save_pointer_of_first_devise;

    for(auto& tr: treads){
        tr.join();
    }

    pcap_freealldevs(devises);

    return 0;

}

*/

