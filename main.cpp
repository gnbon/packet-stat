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

struct PacketStatistics
{
    int tx_packets;
    int tx_bytes;
    int rx_packets;
    int rx_bytes;

    PacketStatistics() {tx_packets = 0; tx_bytes = 0; rx_packets = 0; rx_bytes = 0;};
    void print() {printf("tx_packets: %d, tx_bytes: %d, rx_packets: %d, rx_bytes: %d\n", tx_packets, tx_bytes, rx_packets, rx_bytes);};
};

struct KeyMac {
    uint8_t eth_addr[ETH_ALEN];

    bool operator<(KeyMac const& other) const {
        for (int i = 0; i < ETH_ALEN; i++) {
		    if (eth_addr[i] != other.eth_addr[i]) {
		        if (eth_addr[i] < other.eth_addr[i])
                    return true;
                else 
                    return false;
		    }
        }
        return false;
    }
};

std::map<KeyMac, PacketStatistics> stat_mac;
std::map<uint32_t, PacketStatistics> stat_ip;

void callback_stat(unsigned char* useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    PacketStatistics* stat_tmp = nullptr;
    
    auto eth = (ether_header *)packet;

    KeyMac src_mac;
    KeyMac dst_mac;
    memcpy(src_mac.eth_addr, eth->ether_shost, sizeof(ether_addr));
    memcpy(dst_mac.eth_addr, eth->ether_dhost, sizeof(ether_addr));

    auto iter_mac = stat_mac.find(src_mac);

    if (iter_mac == stat_mac.end()) 
        iter_mac = stat_mac.insert(std::make_pair(src_mac, PacketStatistics())).first;
    iter_mac->second.tx_packets++;
    iter_mac->second.tx_bytes += pkthdr->len;

    iter_mac = stat_mac.find(dst_mac);

    if (iter_mac == stat_mac.end()) 
        iter_mac = stat_mac.insert(std::make_pair(dst_mac, PacketStatistics())).first;
    iter_mac->second.rx_packets++;
    iter_mac->second.rx_bytes += pkthdr->len;

    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;
    
    packet += sizeof(ether_header);
    auto iph = (ip *)packet;

    in_addr_t src_ip = iph->ip_src.s_addr;
    in_addr_t dst_ip = iph->ip_dst.s_addr;

    auto iter_ip = stat_ip.find(src_ip);

    if (iter_ip == stat_ip.end()) 
        iter_ip = stat_ip.insert(std::make_pair(src_ip, PacketStatistics())).first;
    iter_ip->second.tx_packets++;
    iter_ip->second.tx_bytes += pkthdr->len;

    iter_ip = stat_ip.find(dst_ip);
    if (iter_ip == stat_ip.end()) 
        iter_ip = stat_ip.insert(std::make_pair(dst_ip, PacketStatistics())).first;
    iter_ip->second.rx_packets++;
    iter_ip->second.rx_bytes += pkthdr->len;
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

    for(auto iter_mac=stat_mac.begin(); iter_mac!=stat_mac.end(); iter_mac++) {
        ether_addr ether;
        memcpy(ether.ether_addr_octet, iter_mac->first.eth_addr, sizeof(ether_addr));
        printf("mac addr: %s, ", ether_ntoa(&ether));
        iter_mac->second.print();
    }

    for(auto iter_ip=stat_ip.begin(); iter_ip!=stat_ip.end(); iter_ip++) {
        in_addr in = {iter_ip->first};
        printf("ip addr: %s, ", inet_ntoa(in));
        iter_ip->second.print();
    }

    pcap_close(pcd);
    return 0;
}