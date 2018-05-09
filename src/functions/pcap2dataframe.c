//
// Created by uyatashi on 3/27/18.
//
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/ether.h>
#include <byteswap.h>
#include <linux/udp.h>


#define REVERSE_SHORT(n) ((unsigned short) (((n & 0xFF) << 8) | \
                                            ((n & 0xFF00) >> 8)))

char *timestamp_string(struct timeval ts);

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};

/* UDP header */
struct sniff_udp {
    u_short th_sport;
    u_short th_dport;
    u_short udp_len;
    u_short udp_sum;
};

int main(int argc, char *argv[])
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    //printf("Device: %s\n", dev);

    pcap_t *pcap;

    /* Skip over the program name. */
    ++argv; --argc;

    /* We expect exactly one argument, the name of the file to dump. */
    if ( argc != 1 ) {
        fprintf(stderr, "Please provide the .pcap file as an argument.\n");
        exit(1);
    }

    //handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    pcap = pcap_open_offline(argv[0], errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "error reading pcap file: %s\n", errbuf);
        exit(1);
    }

    if (pcap_datalink(pcap) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        return(2);
    }

    /* ethernet headers are always exactly 14 bytes */
    #define SIZE_ETHERNET 14

    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const struct sniff_udp *udp; /* The TCP header */
    const char *payload; /* Packet payload */
    struct pcap_pkthdr packet_header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    u_int size_ip;
    u_int size_tcp;
    char* timestamp;
    int p_caplen, p_len;

    while ((packet = pcap_next(pcap, &packet_header)) != NULL) {

        timestamp = timestamp_string(packet_header.ts);
        printf("Timestamp: %s | ", timestamp);

        p_caplen = packet_header.caplen;
        p_len = packet_header.len;
        printf("Packet capture length: %d | ", p_caplen);
        printf("Packet total length %d\n", p_len);

        //ETHERNET HEADER - START
        ethernet = (struct sniff_ethernet *) (packet); //Always exists, always 14bytes
        unsigned short ether_type = ntohs(ethernet->ether_type);
        //printf("%hu", ether_type);

        printf("ETHER TYPE: ");
        if (ether_type == ETHERTYPE_IP) {
            printf("IP | ");
            //return 0;
        } else  if (ether_type == ETHERTYPE_ARP) {
            printf("ARP | ");
            //return 1;
        } else  if (ntohs(ether_type) == ETHERTYPE_REVARP) {
            printf("Reverse ARP | ");
            //return 2;
        }
        //printf("%x", ntohs(ethernet->ether_type))

        //char *tmp_addr;
        char *src_ether, *temp_ether;
        struct ether_addr src, dst;
        char dst_ether[18];

        memcpy(&dst, ethernet->ether_dhost, sizeof(dst));
        temp_ether = ether_ntoa(&dst);
        //strncpy(dst_ether, temp_ether,strlen(temp_ether));
        strncpy(dst_ether, temp_ether, strlen(temp_ether)-1);
        dst_ether[17] = '\0';

        memcpy(&src, ethernet->ether_shost, sizeof(src));
        src_ether = ether_ntoa(&src);

        printf("ETHER SRC: %s | ETHER DST: %s\n", src_ether, dst_ether);
        //ETHERNET HEADER - END


        //IP HEADER - START
        ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
        u_char ip_vhl;		/* version << 4 | header length >> 2 */
        u_char ip_tos;		/* type of service */
        u_short ip_len;		/* total length */
        u_short ip_id;		/* identification */
        u_short ip_off;		/* fragment offset field */
        u_char ip_ttl;		/* time to live */
        u_char ip_p;		/* protocol */
        u_short ip_sum;		/* checksum */

        u_char ip_version = IP_V(ip);
        printf("IP Version: %u | ", ip_version);

        //Will be needed to distinguish ipv4 and ipv6 addresses later
        /*
        if (ip_version == (unsigned char)4) {
            printf("IPV4");
        }*/

        u_char ip_headerlen = IP_HL(ip);
        printf("IP Header len: %u | ", ip_headerlen);

        ip_tos = ip->ip_tos;
        printf("IP TOS: %u | ", ip_tos);

        ip_len = REVERSE_SHORT(ip->ip_len);
        printf("IP length: %hu |", ip_len);

        ip_id = REVERSE_SHORT(ip->ip_id);
        printf("IP id: %hu | ", ip_id);

        //Needs to be checked
        ip_off = ip->ip_off;
        printf("IP fragment offset: %hu | ", ip_off);

        ip_ttl = ip->ip_ttl;
        printf("IP ttl: %hu | ", ip_ttl);

        ip_p = ip->ip_p;
        printf("IP protocol: %u | ", ip_p);

        ip_sum = REVERSE_SHORT(ip->ip_sum);
        printf("IP checksum: 0x%x | ", ip_sum);
        size_ip = ip_headerlen * 4;
        /*
        if (size_ip < 20) {
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
            //return;
            continue;
        }
        tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp) * 4;
        if (size_tcp < 20) {
            printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
            //return;
            continue;
        }
        payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp); */

        //struct in_addr src_ip, dst_ip;
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ip->ip_src.s_addr), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->ip_dst.s_addr), dst_ip, INET_ADDRSTRLEN);

        printf("IP SRC: %s | IP DST: %s\n", src_ip, dst_ip);

        //IP HEADER - END

        //TCP
        if ((int)(ip_p) == 6) {

            //TCP HEADER - START
            tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);

            u_short th_sport;	/* source port */
            u_short th_dport;	/* destination port */
            tcp_seq th_seq;		/* sequence number */
            tcp_seq th_ack;		/* acknowledgement number */
            u_char th_offx2;	/* data offset, rsvd */
            u_short th_flags;
            u_short th_urp;

            th_sport = REVERSE_SHORT(tcp->th_sport);
            printf("TCP src_port: %hu | ", th_sport);

            th_dport = REVERSE_SHORT(tcp->th_dport);
            printf("TCP dst_port: %hu | ", th_dport);

            th_seq = __bswap_32(tcp->th_seq);
            printf("TCP seq number: 0x%x | ", th_seq);

            th_ack = __bswap_32(tcp->th_ack);
            printf("TCP ack number: 0x%x | ", th_ack);

            th_offx2 = tcp->th_offx2;
            printf("TCP data offset: %u | ", th_offx2);

            th_flags = (unsigned short)tcp->th_flags;
            printf("TCP Flags: %x | ", th_flags);

            th_urp = tcp->th_urp;
            printf("TCP Urgent pointer: %x\n", th_urp);

            size_tcp = TH_OFF(tcp) * 4;
            int size_headers = SIZE_ETHERNET + size_ip + size_tcp;
            payload = (void *) (packet + size_headers);

            //Needs to be extended. For now I will just store it as a hex/binary stream.
            printf("Payload: ");
            int curByte;
            for (int i=0; i<p_caplen-size_headers; i++ ) {
                curByte = payload[i];
                printf("%i", curByte & 0x01);
            }

        //TCP HEADER - END
        }
        //UDP HEADER - START
        else if ((int)(ip_p) == 17) {
            udp = (struct sniff_udp *) (packet + SIZE_ETHERNET + size_ip);
            u_short th_sport;	/* source port */
            u_short th_dport;	/* destination port */
            u_short udp_len;
            u_short udp_sum;

            th_sport = REVERSE_SHORT(udp->th_sport);
            printf("UDP src_port: %hu | ", th_sport);

            th_dport = REVERSE_SHORT(udp->th_dport);
            printf("UDP dst_port: %hu | ", th_dport);

            udp_len = REVERSE_SHORT(udp->udp_len);
            printf("UDP length: %hu | ", udp_len);

            udp_sum = REVERSE_SHORT(udp->udp_sum);
            printf("UDP checksum: 0x%x\n", udp_sum);
        }
        //UDP HEADER - END
        printf("\n\n");
    }
    return(0);
}

//Converts timestamp to string
char *timestamp_string(struct timeval ts) {
    static char timestamp_string_buf[256];

    sprintf(timestamp_string_buf, "%d.%09d",
            (int) ts.tv_sec, (int) ts.tv_usec);

    return timestamp_string_buf;
}