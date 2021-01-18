#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <map>

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

struct Stat
{
    int tx_packet;
    int tx_byte;
    int rx_packet;
    int rx_byte;

    Stat() {tx_packet = 0; tx_byte = 0; rx_packet = 0; rx_byte = 0;};
};

struct ether_key : public ether_addr {
    bool operator<(ether_key const& rhs) const {
        for (int i = 0; i < ETH_ALEN; i++) {
            if (ether_addr_octet[i] != rhs.ether_addr_octet[i]) {
                if (ether_addr_octet[i] < rhs.ether_addr_octet[i]) return true;
                else return false;
            }
        }
        return false;
    }
};

struct EthStat {
    typedef std::map<ether_key, Stat> EthMap_t;
    EthMap_t EthMap;

    void process_packet(const struct pcap_pkthdr *pkthdr, const u_char* packet) {
        auto eth = (ether_header *)packet;

        ether_key src, dst;
        EthMap_t::iterator iter;

        memcpy(src.ether_addr_octet, eth->ether_shost, ETH_ALEN);
        memcpy(dst.ether_addr_octet, eth->ether_dhost, ETH_ALEN);
        
        iter = EthMap.find(src);
        if (iter == EthMap.end()) iter = EthMap.insert(std::make_pair(src, Stat())).first;
        iter->second.tx_packet++;
        iter->second.tx_byte += pkthdr->len;

        iter = EthMap.find(dst);
        if (iter == EthMap.end()) iter = EthMap.insert(std::make_pair(dst, Stat())).first;
        iter->second.rx_packet++;
        iter->second.rx_byte += pkthdr->len;
    }

    void print_stat() {
        for(auto iter = EthMap.begin(); iter!=EthMap.end(); iter++) {
            ether_addr *ethernet = (ether_addr *)iter->first.ether_addr_octet;
            Stat stat = iter->second;        

            printf("mac addr: %s, ", ether_ntoa(ethernet));
            printf("tx_packet: %d, tx_byte: %d, rx_packet: %d, rx_byte: %d\n", stat.tx_packet, stat.tx_byte, stat.rx_packet, stat.rx_byte);
        }   
    }
};

struct IpStat {
    typedef std::map<uint32_t, Stat> IpMap_t;
    IpMap_t IpMap;

    void process_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        auto iph = (ip *)packet;

        uint32_t src = iph->ip_src.s_addr;
        uint32_t dst = iph->ip_dst.s_addr;
        IpMap_t::iterator iter;

        iter = IpMap.find(src);
        if (iter == IpMap.end()) iter = IpMap.insert(std::make_pair(src, Stat())).first;
        iter->second.tx_packet++;
        iter->second.tx_byte += pkthdr->len;

        iter = IpMap.find(dst);
        if (iter == IpMap.end()) iter = IpMap.insert(std::make_pair(dst, Stat())).first;
        iter->second.rx_packet++;
        iter->second.rx_byte += pkthdr->len;
    }

    void print_stat() {
        for(auto iter = IpMap.begin(); iter != IpMap.end(); iter++) {
            in_addr ip = {iter->first};
            Stat stat = iter->second;
            
            printf("ip addr: %s, ", inet_ntoa(ip));
            printf("tx_packet: %d, tx_byte: %d, rx_packet: %d, rx_byte: %d\n", stat.tx_packet, stat.tx_byte, stat.rx_packet, stat.rx_byte);
        }
    }
};

struct TcpStat {
    typedef std::pair<uint32_t, uint16_t> TcpKey_t;
    typedef std::map<std::pair<uint32_t, uint16_t>, Stat> TcpMap_t; // <<ip_address, port>, Stat>
    TcpMap_t TcpMap;

    void process_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        auto iph = (ip *)packet;
        auto tcph = (tcphdr *)(packet + iph->ip_hl * 4);

        TcpKey_t src = std::make_pair(iph->ip_src.s_addr, tcph->source);
        TcpKey_t dst = std::make_pair(iph->ip_dst.s_addr, tcph->dest);
        TcpMap_t::iterator iter;

        iter = TcpMap.find(src);
        if (iter == TcpMap.end()) iter = TcpMap.insert(std::make_pair(src, Stat())).first;
        iter->second.tx_packet++;
        iter->second.tx_byte += pkthdr->len;

        iter = TcpMap.find(dst);
        if (iter == TcpMap.end()) iter = TcpMap.insert(std::make_pair(dst, Stat())).first;
        iter->second.rx_packet++;
        iter->second.rx_byte += pkthdr->len;
    }

    void print_stat() {
        for(auto iter = TcpMap.begin(); iter != TcpMap.end(); iter++) {
            in_addr ip = {iter->first.first};
            uint16_t tcp = iter->first.second;
            Stat stat = iter->second;
            
            printf("ip addr: %s, tcp port: %d, ", inet_ntoa(ip), ntohs(tcp));
            printf("tx_packet: %d, tx_byte: %d, rx_packet: %d, rx_byte: %d\n", stat.tx_packet, stat.tx_byte, stat.rx_packet, stat.rx_byte);
        }
    }
};

struct UdpStat {
    typedef std::pair<uint32_t, uint16_t> UdpKey_t;
    typedef std::map<std::pair<uint32_t, uint16_t>, Stat> UdpMap_t; // <<ip_address, port>, Stat>
    UdpMap_t UdpMap;

    void process_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
        auto iph = (ip *)packet;
        auto tcph = (tcphdr *)(packet + iph->ip_hl * 4);

        UdpKey_t src = std::make_pair(iph->ip_src.s_addr, tcph->source);
        UdpKey_t dst = std::make_pair(iph->ip_dst.s_addr, tcph->dest);
        UdpMap_t::iterator iter;

        iter = UdpMap.find(src);
        if (iter == UdpMap.end()) iter = UdpMap.insert(std::make_pair(src, Stat())).first;
        iter->second.tx_packet++;
        iter->second.tx_byte += pkthdr->len;

        iter = UdpMap.find(dst);
        if (iter == UdpMap.end()) iter = UdpMap.insert(std::make_pair(dst, Stat())).first;
        iter->second.rx_packet++;
        iter->second.rx_byte += pkthdr->len;
    }

    void print_stat() {
        for(auto iter = UdpMap.begin(); iter != UdpMap.end(); iter++) {
            in_addr ip = {iter->first.first};
            uint16_t udp = iter->first.second;
            Stat stat = iter->second;
            
            printf("ip addr: %s, udp port: %d, ", inet_ntoa(ip), ntohs(udp));
            printf("tx_packet: %d, tx_byte: %d, rx_packet: %d, rx_byte: %d\n", stat.tx_packet, stat.tx_byte, stat.rx_packet, stat.rx_byte);
        }
    }
};

IpStat ipstat;
EthStat ethstat;
TcpStat tcpstat;
UdpStat udpstat;

void callback_stat(unsigned char* useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    ethstat.process_packet(pkthdr, packet);

    if (ntohs(((ether_header *)packet)->ether_type) == ETHERTYPE_IP) {
        packet += sizeof(ether_header);
        ipstat.process_packet(pkthdr, packet);
        
        if (((ip *)packet)->ip_p == IPPROTO_TCP) 
            tcpstat.process_packet(pkthdr, packet);
        if (((ip *)packet)->ip_p == IPPROTO_UDP) 
            udpstat.process_packet(pkthdr, packet);
    }
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc != 2) {
        printf("syntax : %s <pcap file>\n", argv[0]);
        printf("sample : %s test.pcap\n", argv[0]);
        exit(1);
    }

    pcap_t *pcd = pcap_open_offline(argv[1], errbuf);
    if (!pcd) {
        printf("%s\n", errbuf);
        exit(1);
    }

    pcap_loop(pcd, 0, callback_stat, NULL);

    ethstat.print_stat();    
    ipstat.print_stat();
    tcpstat.print_stat();
    udpstat.print_stat();

    pcap_close(pcd);
    return 0;
}