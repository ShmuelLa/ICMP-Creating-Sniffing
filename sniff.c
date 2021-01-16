#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<net/ethernet.h>

#define	ETHER_ADDR_LEN 6

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    printf("%d dhost =\n" ,ntohs(eth->ether_dhost));
    printf("%d shost =\n" ,ntohs(eth->ether_shost));
    printf("%d type =\n" ,ntohs(eth->ether_type));

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));  
    printf("         To: %s\n", inet_ntoa(ip->iph_destip)); 
        switch(ip->iph_protocol) {                               
            case IPPROTO_TCP:
                printf("   Protocol: TCP\n");
                return;
            case IPPROTO_UDP:
                printf("   Protocol: UDP\n");
                return;
            case IPPROTO_ICMP:
                printf("   Protocol: ICMP\n");
                return;
            default:
                printf("   Protocol: others\n");
                return;
        }
    }
    printf("\n");

    //struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethheader));
}

int main() {
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "ip proto icmp";
    
    //open live pcap session, we sniif on "any" interface which shows everything
    handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        perror("Live session opening error");
    }

    pcap_compile(handle, &fp, filter_exp, 0, net);      
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);                
    
    //close the socket
    pcap_close(handle);
    return 0;
}