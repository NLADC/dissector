/* Compile :  clang -Wall -I/usr/include/json-c/ -o pcap2json pcap2json.c -ljson-c -lpcap */


#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<json.h>

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int );

FILE *jsonfile;
char *json_string;
struct json_object *jobj, *jobj_ether, *jobj_ip, *jobj_tcp, *jobj_udp, *jobj_icmp;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Skip over the program name. */
    ++argv; --argc;

    /* We expect exactly one argument, the name of the file to dump. */
    if ( argc != 1 ) {
        fprintf(stderr, "Please provide the .pcap file as an argument.\n");
        exit(1);
    }

    handle = pcap_open_offline(argv[0], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "error reading pcap file: %s\n", errbuf);
        exit(1);
    }

    jobj = json_object_new_object();
    jobj_ether = json_object_new_object();
    jobj_ip = json_object_new_object();
    jobj_tcp = json_object_new_object();
    jobj_udp = json_object_new_object();
    jobj_icmp = json_object_new_object();

    jsonfile=fopen("json_file.txt","w");
    if(jsonfile==NULL)
    {
        printf("Unable to create .json file to write to.");
    }
    json_string = (char*)malloc(3000);
    pcap_loop(handle , -1 , process_packet , NULL);
    free(json_string); free(jobj); free(jobj_ether); free(jobj_ip); free(jobj_tcp); free(jobj_udp); free(jobj_icmp);
    return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len; //raw-size
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            print_icmp_packet(buffer , size);
            break;

        case 2:  //IGMP Protocol
            break;

        case 6:  //TCP Protocol
            print_tcp_packet(buffer , size);
            break;

        case 17: //UDP Protocol
            print_udp_packet(buffer , size);
            break;

        default: //Some Other Protocol like ARP etc.
            break;
    }
    fprintf(jsonfile,"%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN));
}

void print_ethernet_header(const u_char *Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    char *temp =(char*)malloc(sizeof(char)*20);
    sprintf(temp, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);
    json_object_object_add(jobj_ether, "dst", json_object_new_string(temp));
    sprintf(temp, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);
    json_object_object_add(jobj_ether, "src", json_object_new_string(temp));
    sprintf(temp,"%u",(unsigned short)eth->h_proto);
    json_object_object_add(jobj_ether, "proto", json_object_new_string(temp));
    free(temp);

    sprintf(json_string, "%s", json_object_to_json_string_ext(jobj_ether, JSON_C_TO_STRING_PLAIN));
    json_object_object_add(jobj, "ether", json_object_new_string(json_string));
    return;
}

void print_ip_header(const u_char * Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    char *temp =(char*)malloc(sizeof(char)*50);
    sprintf(temp, "%d",(unsigned int)iph->version);
    json_object_object_add(jobj_ip, "version", json_object_new_string(temp));
    sprintf(temp, "%d",((unsigned int)(iph->ihl))*4);
    json_object_object_add(jobj_ip, "hdrlen", json_object_new_string(temp));
    sprintf(temp, "%d",(unsigned int)iph->tos);
    json_object_object_add(jobj_ip, "tos", json_object_new_string(temp));
    sprintf(temp, "%d",ntohs(iph->tot_len));
    json_object_object_add(jobj_ip, "len", json_object_new_string(temp));
    sprintf(temp, "%d",ntohs(iph->id));
    json_object_object_add(jobj_ip, "id", json_object_new_string(temp));
    sprintf(temp, "%d",(unsigned int)iph->ttl);
    json_object_object_add(jobj_ip, "ttl", json_object_new_string(temp));
    sprintf(temp, "%d",(unsigned int)iph->protocol);
    json_object_object_add(jobj_ip, "proto", json_object_new_string(temp));
    sprintf(temp, "%d", ntohs(iph->check));
    json_object_object_add(jobj_ip, "checksum", json_object_new_string(temp));
    sprintf(temp, "%s" , inet_ntoa(source.sin_addr));
    json_object_object_add(jobj_ip, "src", json_object_new_string(temp));
    sprintf(temp, "%s" , inet_ntoa(dest.sin_addr));
    json_object_object_add(jobj_ip, "dst", json_object_new_string(temp));
    free(temp);

    sprintf(json_string, "%s", json_object_to_json_string_ext(jobj_ip, JSON_C_TO_STRING_PLAIN));
    json_object_object_add(jobj, "ip", json_object_new_string(json_string));

    return;
}

void print_tcp_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;

    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    print_ip_header(Buffer,Size);

    char *temp =(char*)malloc(sizeof(char)*50);
    sprintf(temp, "%u",ntohs(tcph->source));
    json_object_object_add(jobj_tcp, "sport", json_object_new_string(temp));
    sprintf(temp, "%u",ntohs(tcph->dest));
    json_object_object_add(jobj_tcp, "dport", json_object_new_string(temp));
    sprintf(temp, "%u",ntohl(tcph->seq));
    json_object_object_add(jobj_tcp, "seq_num", json_object_new_string(temp));
    sprintf(temp, "%u",ntohl(tcph->ack_seq));
    json_object_object_add(jobj_tcp, "ack_num", json_object_new_string(temp));
    sprintf(temp, "%d", (unsigned int)tcph->doff*4);
    json_object_object_add(jobj_tcp, "hdrlen", json_object_new_string(temp));
    sprintf(temp, "%d", (unsigned int)tcph->urg);
    json_object_object_add(jobj_tcp, "flags_urg", json_object_new_string(temp));
    sprintf(temp, "%d", (unsigned int)tcph->ack);
    json_object_object_add(jobj_tcp, "flags_ack", json_object_new_string(temp));
    sprintf(temp, "%d", (unsigned int)tcph->psh);
    json_object_object_add(jobj_tcp, "flags_psh", json_object_new_string(temp));
    sprintf(temp, "%d", (unsigned int)tcph->rst);
    json_object_object_add(jobj_tcp, "flags_rst", json_object_new_string(temp));
    sprintf(temp, "%d", (unsigned int)tcph->syn);
    json_object_object_add(jobj_tcp, "flags_syn", json_object_new_string(temp));
    sprintf(temp, "%d", (unsigned int)tcph->fin);
    json_object_object_add(jobj_tcp, "flags_fin", json_object_new_string(temp));
    sprintf(temp, "%d", ntohs(tcph->window));
    json_object_object_add(jobj_tcp, "window", json_object_new_string(temp));
    sprintf(temp, "%d", ntohs(tcph->check));
    json_object_object_add(jobj_tcp, "checksum", json_object_new_string(temp));
    sprintf(temp, "%d", tcph->urg_ptr);
    json_object_object_add(jobj_tcp, "urg_ptr", json_object_new_string(temp));
    free(temp);

    char *temp2 = (char*)malloc(sizeof(char)*10000); //ARBITRARY

    int i, temp2_len;
    temp2_len = 0;
    for(i=0 ; i < (Size - header_size); i++) {
        sprintf(temp2 + temp2_len, "%02X",(unsigned int)(Buffer+header_size)[i]);
        temp2_len = strlen(temp2);
    }
    json_object_object_add(jobj_tcp, "payload", json_object_new_string(temp2));
    free(temp2);

    sprintf(json_string, "%s", json_object_to_json_string_ext(jobj_tcp, JSON_C_TO_STRING_PLAIN));
    json_object_object_add(jobj, "tcp", json_object_new_string(json_string));

    return;
}

void print_udp_packet(const u_char *Buffer , int Size)
{

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    print_ip_header(Buffer,Size);

    char *temp =(char*)malloc(sizeof(char)*50);
    sprintf(temp, "%d" , ntohs(udph->source));
    json_object_object_add(jobj_udp, "sport", json_object_new_string(temp));
    sprintf(temp, "%d" , ntohs(udph->dest));
    json_object_object_add(jobj_udp, "dport", json_object_new_string(temp));
    sprintf(temp, "%d" , ntohs(udph->len));
    json_object_object_add(jobj_udp, "len", json_object_new_string(temp));
    sprintf(temp,  "%d" , ntohs(udph->check));
    json_object_object_add(jobj_udp, "checksum", json_object_new_string(temp));
    free(temp);

    char *temp2 = (char*)malloc(sizeof(char)*10000); //ARBITRARY

    int i, temp2_len;
    temp2_len = 0;
    for(i=0 ; i < (Size - header_size); i++) {
        sprintf(temp2 + temp2_len, "%02X",(unsigned int)(Buffer+header_size)[i]);
        temp2_len = strlen(temp2);
    }
    json_object_object_add(jobj_udp, "payload", json_object_new_string(temp2));

    free(temp2);

    sprintf(json_string, "%s", json_object_to_json_string_ext(jobj_udp, JSON_C_TO_STRING_PLAIN));
    json_object_object_add(jobj, "udp", json_object_new_string(json_string));

    return;
}

void print_icmp_packet(const u_char * Buffer , int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

    print_ip_header(Buffer , Size);

    char *temp =(char*)malloc(sizeof(char)*50);
    sprintf(temp, "%d", (unsigned int)(icmph->type));
    json_object_object_add(jobj_icmp, "icmp_type", json_object_new_string(temp));
    sprintf(temp, "%d", (unsigned int)(icmph->code));
    json_object_object_add(jobj_icmp, "icmp_code", json_object_new_string(temp));
    sprintf(temp, "%d", ntohs(icmph->checksum));
    json_object_object_add(jobj_icmp, "icmp_checksum", json_object_new_string(temp));
    free(temp);

    char *temp2 = (char*)malloc(sizeof(char)*10000); //ARBITRARY

    int i, temp2_len;
    temp2_len = 0;
    for(i=0 ; i < (Size - header_size); i++) {
        sprintf(temp2 + temp2_len, "%02X",(unsigned int)(Buffer+header_size)[i]);
        temp2_len = strlen(temp2);
    }
    json_object_object_add(jobj_icmp, "payload", json_object_new_string(temp2));
    free(temp2);

    sprintf(json_string, "%s", json_object_to_json_string_ext(jobj_icmp, JSON_C_TO_STRING_PLAIN));
    json_object_object_add(jobj, "ip", json_object_new_string(json_string));
    return;
}