/* Compile :  gcc -Wall -I/usr/local/include/json-c/ -o pcap2json pcap2json.c -ljson-c -lpcap */


#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/if_ether.h>
#include<netinet/ip.h>   //Provides declarations for icmp header
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
//#include<netinet/dns.h>
#include<json.h>

//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

//Created because something didn't work as it is supposed to
struct ANSWER
{
    unsigned short qtype;
    unsigned short qclass;
    unsigned int ttl;
    unsigned short rdlen;
};

struct DNS_CAA
{
    unsigned char flags;
    unsigned char tag_len;
};

//Incomplete
struct DNS_LOC
{
    unsigned short version;
    unsigned short size;
    unsigned short horiz_pre;
    unsigned short vert_pre;

    unsigned int latitude;
}

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int );

void print_dns(const u_char* Buffer, int Size, int header_size);
int print_dns_question(const u_char* Buffer,int Size,int offset);
int print_dns_answer(const u_char* Buffer,int Size, int header_size, int offset);
u_char* qnameReader(const u_char* Buffer, int offset,int* qname_len);


u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);
static char* hex_to_ip(const char *input);
void ipv6_to_str_unexpanded(char * str, const struct in6_addr * addr);



FILE *jsonfile;
char *json_string;
struct json_object *jobj, *jobj_ether, *jobj_ip, *jobj_tcp, *jobj_udp, *jobj_icmp, *jobj_dns;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;

//#define JSON_C_TO_STRING_NOSLASHESCAPE (1<<4)
#define T_A 1 //Ipv4 address

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE]; //not used

    /* Skip over the program name. */
    ++argv; --argc;

    /* We expect exactly one argument, the name of the pcap file. */
    if ( argc != 1 ) {
        fprintf(stderr, "Please provide the .pcap file as an argument.\n");
        exit(1);
    }

    /* Open the pcap file */
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
    jobj_dns = json_object_new_object();

    /* The json file we will output in the end */
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

    fprintf(jsonfile,"%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE));
    //printf("%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE));
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

    sprintf(json_string, "%s", json_object_to_json_string_ext(jobj_ether, JSON_C_TO_STRING_NOSLASHESCAPE));
    json_object_object_add(jobj, "ether", json_object_get(jobj_ether));
    return;
}

void print_ip_header(const u_char * Buffer, int Size)
{
    //print_ethernet_header(Buffer , Size);

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    struct sockaddr_in source,dest;

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
    sprintf(temp, "%d",((int)(iph->frag_off) == 32) ? 1 : 0);
    json_object_object_add(jobj_ip, "is_fragmented", json_object_new_string(temp));
    sprintf(temp, "%d",(unsigned int)iph->ttl);
    json_object_object_add(jobj_ip, "ttl", json_object_new_string(temp));
    sprintf(temp, "%d", (unsigned int)iph->protocol);
    json_object_object_add(jobj,"ip_proto", json_object_new_string(temp));
    sprintf(temp, "%d", ntohs(iph->check));
    json_object_object_add(jobj_ip, "checksum", json_object_new_string(temp));
    sprintf(temp, "%s", inet_ntoa(source.sin_addr));
    json_object_object_add(jobj, "ip_src", json_object_new_string(temp));
    sprintf(temp, "%s", inet_ntoa(dest.sin_addr));
    json_object_object_add(jobj, "ip_dst", json_object_new_string(temp));
    free(temp);

    sprintf(json_string, "%s", json_object_to_json_string_ext(jobj_ip, JSON_C_TO_STRING_NOSLASHESCAPE));
    json_object_object_add(jobj, "ip_header", json_object_new_string(json_string));

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

    char *temp =(char*)malloc(sizeof(char)*50); //arbitrary
    //sprintf(temp, "%u",ntohs(tcph->source));
    //json_object_object_add(jobj_tcp, "sport", json_object_new_string(temp));
    //sprintf(temp, "%u",ntohs(tcph->dest));
    //json_object_object_add(jobj_tcp, "dport", json_object_new_string(temp));
    sprintf(temp, "%u",ntohs(tcph->source));
    json_object_object_add(jobj, "port_src", json_object_new_string(temp));
    sprintf(temp, "%u",ntohs(tcph->dest));
    json_object_object_add(jobj, "port_dst", json_object_new_string(temp));



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

    sprintf(json_string, "%s", json_object_to_json_string_ext(jobj_tcp, JSON_C_TO_STRING_NOSLASHESCAPE));
    json_object_object_add(jobj, "transport_header", json_object_new_string(json_string));

    char *temp2 = (char*)malloc(sizeof(char)*10000); //ARBITRARY

    int i, temp2_len;
    temp2_len = 0;
    for(i=0 ; i < (Size - header_size); i++) {
        sprintf(temp2 + temp2_len, "%02X",(unsigned int)(Buffer+header_size)[i]);
        temp2_len = strlen(temp2);
    }
    json_object_object_add(jobj_tcp, "payload", json_object_new_string(temp2));
    free(temp2);

    return;
}

void print_udp_packet(const u_char *Buffer , int Size)
{

    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    unsigned short iphdrlen = iph->ihl*4; //4 is magic :D, ref = libpcap packet sniffer

    struct udphdr *udph = (struct udphdr*)(Buffer + sizeof(struct ethhdr) + iphdrlen);

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
    int sport = ntohs(udph->source);
    int dport = ntohs(udph->dest);

    //print_ip_header(Buffer,Size);

    char *temp =(char*)malloc(sizeof(char)*50);
    sprintf(temp, "%d" , sport);
    json_object_object_add(jobj, "port_src", json_object_new_string(temp));
    sprintf(temp, "%d" , dport);
    json_object_object_add(jobj, "port_dst", json_object_new_string(temp));
    sprintf(temp, "%d" , ntohs(udph->len));
    json_object_object_add(jobj_udp, "len", json_object_new_string(temp));
    sprintf(temp,  "0x%x" , ntohs(udph->check));
    json_object_object_add(jobj_udp, "checksum", json_object_new_string(temp));
    free(temp);

    //sprintf(json_string, "%s", json_object_to_json_string_ext(jobj_udp, JSON_C_TO_STRING_NOSLASHESCAPE));
    json_object_object_add(jobj, "transport_header", json_object_get(jobj_udp));


    if (sport == 53 || dport == 53) {
      print_dns(Buffer,Size,header_size);
      /*unsigned short q_count; // number of question entries
      unsigned short ans_count; // number of answer entries
      unsigned short auth_count; // number of authority entries
      unsigned short add_count; // number of resource entries*/
      //printf("\n\n\n");
    //sprintf(json_string, "%s", json_object_to_json_string_ext(jobj_dns, JSON_C_TO_STRING_NOSLASHESCAPE));
    json_object_object_add(jobj, "payload", json_object_get(jobj_dns));

    }
    else {
      char *temp2 = (char*)malloc(sizeof(char)*10000); //ARBITRARY

      int i, temp2_len;
      temp2_len = 0;
      for(i=0 ; i < (Size - header_size); i++) {
          sprintf(temp2 + temp2_len, "%02X",(unsigned int)(Buffer+header_size)[i]);
          temp2_len = strlen(temp2);
      }
      json_object_object_add(jobj, "payload", json_object_new_string(temp2));

      free(temp2);
    }
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
    json_object_object_add(jobj_icmp, "type", json_object_new_string(temp));
    sprintf(temp, "%d", (unsigned int)(icmph->code));
    json_object_object_add(jobj_icmp, "code", json_object_new_string(temp));
    sprintf(temp, "%d", ntohs(icmph->checksum));
    json_object_object_add(jobj_icmp, "checksum", json_object_new_string(temp));
    free(temp);

    sprintf(json_string, "%s", json_object_to_json_string_ext(jobj_icmp, JSON_C_TO_STRING_NOSLASHESCAPE));
    json_object_object_add(jobj, "transport_header", json_object_new_string(json_string));

    char *temp2 = (char*)malloc(sizeof(char)*10000); //ARBITRARY

    int i, temp2_len;
    temp2_len = 0;
    for(i=0 ; i < (Size - header_size); i++) {
        sprintf(temp2 + temp2_len, "%02X",(unsigned int)(Buffer+header_size)[i]);
        temp2_len = strlen(temp2);
    }
    json_object_object_add(jobj, "payload", json_object_new_string(temp2));
    free(temp2);

    return;
}

void print_dns(const u_char* Buffer, int Size, int header_size) {
      struct DNS_HEADER *dns = NULL;

      //unsigned char buf[65536], *qname, *reader;
      //struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server

      //Set the DNS structure to standard queries
      dns = (struct DNS_HEADER*)(Buffer+header_size);

      int q_count = ntohs(dns->q_count);
      int ans_count = ntohs(dns->ans_count);
      int auth_count = ntohs(dns->auth_count);
      int add_count = ntohs(dns->add_count);

      char *temp3 =(char*)malloc(sizeof(char)*2000); // kind of arbitrary value used here - 2000 - POSSIBLY 8
      sprintf(temp3, "0x%x" , ntohs(dns->id));
      json_object_object_add(jobj_dns, "id", json_object_new_string(temp3));
      sprintf(temp3, "%x" , ntohs(dns->qr));
      json_object_object_add(jobj_dns, "query_flag", json_object_new_string(temp3));
      sprintf(temp3, "0x%x" , ntohs(dns->opcode));
      json_object_object_add(jobj_dns, "opcode", json_object_new_string(temp3));
      sprintf(temp3, "%x", dns->aa);
      json_object_object_add(jobj_dns, "authorative_answer", json_object_new_string(temp3));
      sprintf(temp3,  "%x" , dns->tc);
      json_object_object_add(jobj_dns, "truncated", json_object_new_string(temp3));
      sprintf(temp3, "%x", dns->rd);
      json_object_object_add(jobj_dns, "recusion_desired", json_object_new_string(temp3));
      sprintf(temp3, "%x", dns->ra);
      json_object_object_add(jobj_dns, "recursion_available", json_object_new_string(temp3));
      sprintf(temp3, "%x", dns->z);
      json_object_object_add(jobj_dns, "z", json_object_new_string(temp3));
      sprintf(temp3, "0x%x", ntohs(dns->rcode));
      json_object_object_add(jobj_dns, "rcode", json_object_new_string(temp3));
      sprintf(temp3, "%x", dns->ad);
      json_object_object_add(jobj_dns, "non_auth_data", json_object_new_string(temp3));
      sprintf(temp3, "%d", q_count);
      json_object_object_add(jobj_dns, "questions", json_object_new_string(temp3));
      sprintf(temp3, "%d", ans_count);
      json_object_object_add(jobj_dns, "answers", json_object_new_string(temp3));
      sprintf(temp3, "%d", auth_count);
      json_object_object_add(jobj_dns, "authorities", json_object_new_string(temp3));
      sprintf(temp3, "%d", add_count);
      json_object_object_add(jobj_dns, "additional", json_object_new_string(temp3));
      free(temp3);

      header_size = header_size + sizeof(struct DNS_HEADER);
      int offset = 0;
      //for multiple questions
      for(int i=0; i<q_count; i++) {
        offset += print_dns_question(Buffer,header_size,offset);
      }

      //DNS response
      if (ans_count != 0) {
        printf("A count: %d\n", ans_count);
        //header_size = header_size + sizeof(struct QUESTION)*q_count;
        header_size = header_size + offset;
        offset = 0;
        for(int i=0; i<ans_count; i++) {
          offset += print_dns_answer(Buffer,Size,header_size,offset);
        }


      }
      return;
}

int print_dns_question(const u_char* Buffer,int header_size,int offset) {
    struct QUESTION *qinfo = NULL;

    u_char* qname;
    int* qname_len = (int*)malloc(sizeof(int));
    int size_of_q;

    qname = qnameReader(Buffer, header_size + offset, qname_len);
    printf("%s\n", qname);
    //printf("Qname len: %d\n", *qname_len);

    qinfo = (struct QUESTION*)(Buffer + header_size + offset + *qname_len + 1);
    printf("qtype: %x\n", htons(qinfo->qtype));
    printf("qclass: %x\n\n", htons(qinfo->qclass));

    size_of_q = *qname_len + sizeof(struct QUESTION);
    free(qname);
    free(qname_len);
    return size_of_q;
}

int print_dns_answer(const u_char* Buffer,int Size, int header_size,int offset) {
    struct ANSWER *qanswer_hdr = NULL;

    u_char* qname;
    int* qname_len = (int*)malloc(sizeof(int));
    int size_of_a = 0;

    qname = qnameReader(Buffer, header_size + offset + 1, qname_len);
	//check possibilities when 0
    if (*qname_len == 0) {
      free(qname);
      //qname = (u_char*)malloc(sizeof(char) * 7);
      qname = "<Root>\0";
      printf("qname ANS: %s\n", qname);
      //*qname_len = 1;
    }
    printf("qname len: %d\n", *qname_len);

    qanswer_hdr = (struct ANSWER*)(Buffer + header_size + offset + *qname_len + 1);
    int qtype = ntohs(qanswer_hdr->qtype);
    int rdlen = ntohs(qanswer_hdr->rdlen);

    printf("qtype: %x\n", qtype);
    printf("qclass: %x\n", ntohs(qanswer_hdr->qclass));
    printf("ttl: %d\n", ntohl(qanswer_hdr->ttl));
    printf("rdlen: %x\n", rdlen);

    size_of_a += sizeof(struct ANSWER) + *qname_len;
    //A
    if (qtype == 1) {
        int* raddr = (int*)(Buffer + header_size + offset + *qname_len + 1 + sizeof(struct ANSWER));

        char* addr = (char*)malloc(sizeof(char) * rdlen + 1);
        sprintf(addr, "%x\0", htonl(*raddr));
        printf("raddr: %s\n", hex_to_ip(addr));

        size_of_a += rdlen * sizeof(char);
        free(addr);
    }
    //AAAA
    else if (qtype == 28) {
        struct in6_addr* raddr = (struct in6_addr*)(Buffer + header_size + offset + *qname_len + 1 + sizeof(struct ANSWER));
        char* addr = (char*)malloc(100);
        ipv6_to_str_unexpanded(addr, raddr);
        printf("ADDR: %s", addr);

        size_of_a += rdlen * sizeof(char);
        free(addr);
    }
    //CAA
    else if (qtype == 257) {
        struct DNS_CAA* caa = (struct DNS_CAA*)(Buffer + header_size + offset + *qname_len + 1 + sizeof(struct ANSWER));
        int tag_len = caa->tag_len;
        printf("CAA flags: %x\n", caa->flags);
        printf("CAA taglen: %x\n", tag_len);

        char* cur_char;
        for(int i=0; i<tag_len;i++) {
          cur_char = Buffer + header_size + offset + *qname_len + 1  + sizeof(struct ANSWER);
          printf("%c", cur_char[i]);
        }
        printf("\n");

        i = 0;
        //1 is the correct but 3 works in some cases (single answer)
        while(i<(Size-(header_size + offset + *qname_len + 1 + sizeof(struct ANSWER) + tag_len))) {
          cur_char = Buffer + header_size + offset + *qname_len + 1 + sizeof(struct ANSWER) + tag_len;
          printf("%c", cur_char[i]);
          i++;
        }
        size_of_a += sizeof(struct DNS_CAA) + tag_len*sizeof(char) + (i-1) * sizeof(char);
        printf("\n");
    }
    //TXT
    else if (qtype == 16) {
        char* txt_len_char = (char*)(Buffer + header_size + offset + *qname_len + 1 + sizeof(struct ANSWER));
        int txt_len = (int)*txt_len_char;
        printf("txt_len: %d\n", txt_len);

        char* cur_char;
        //the -2 and +4 is magic also -- needs testing
        for(int i=0; i<txt_len-2;i++) {
          cur_char = Buffer + header_size + offset + *qname_len +  4  + sizeof(struct ANSWER);
          printf("%c", cur_char[i]);
        }

        size_of_a += sizeof(char) * txt_len + 1;
        printf("\n");
    }
    //MX
    else if (qtype == 15) {
        short* preference = (short*)(Buffer + header_size + offset + *qname_len + 1 + sizeof(struct ANSWER));
        printf("Preference: %x\n", ntohs(*preference));

        u_char* mx_exchange;
        int* mx_exchange_len = (int*)malloc(sizeof(int));
        header_size = header_size + offset + *qname_len + 1 + sizeof(struct ANSWER);
        mx_exchange = qnameReader(Buffer, header_size, mx_exchange_len);

        printf("EXCHANGE: %s\n", mx_exchange);

        size_of_a += sizeof(short) + *mx_exchange_len * sizeof(char) + 2;

        free(mx_exchange);
        free(mx_exchange_len);

    }
    //SOA
    else if (qtype == 6) {
        u_char* primary_ns;
        int* primary_ns_len = (int*)malloc(sizeof(int));
        header_size = header_size + offset + *qname_len + 1 + sizeof(struct ANSWER);
        primary_ns = qnameReader(Buffer, header_size, primary_ns_len);

        printf("Primary nameserver: %s\n", primary_ns);

        size_of_a += *primary_ns_len * sizeof(char) + 2;
        free(primary_ns);
        free(primary_ns_len);
    }
    //NS
    else if (qtype == 2) {
        u_char* nameserver;
        int* nameserver_len = (int*)malloc(sizeof(int));
        header_size = header_size + offset + *qname_len + 1 + sizeof(struct ANSWER);

        nameserver = qnameReader(Buffer, header_size, nameserver_len);

        printf("Name Server: %s\n", nameserver);

        size_of_a += *nameserver_len * sizeof(char) + 2;
        free(nameserver);
        free(nameserver_len);
    }
    //LOC
    else if (qtype == 29) {

    }

    printf("\n");
    //for testing -- not useful
    if (*qname_len != 0) free(qname_len);
    return size_of_a;
}

u_char* qnameReader(const u_char* Buffer, int offset, int* qname_len) {
    u_char* name = (u_char*)malloc(256);

    u_char cur_char;
    u_char dns_char;
    int i, j;

    j=0;
    while(1) {
      cur_char = Buffer[offset];

      if ((int)(cur_char) == 0 || (int)(cur_char) == 192) {
        break;
      }
      else {
        i = 0;
        //printf(":: %d : %d\n", (int)cur_char, i);
        while(i < (int)cur_char) {
          dns_char = Buffer[offset+i+1];
          //printf("%c", dns_char);
          name[j] = dns_char;
          j++;
          i++;
        }
        name[j] = '.';
        j++;
      }
      //printf("Cur_char: %x\n", cur_char);
      offset = offset+i+1;
    }
    name[j-1] = '\0';

    *qname_len = j;
    return name;
}


static char* hex_to_ip(const char *input)
{
    char *output = (char*)malloc(sizeof(char) * 16);
    unsigned int a, b, c, d;

    if (sscanf(input, "%2x%2x%2x%2x", &a, &b, &c, &d) != 4)
        return output;
    sprintf(output, "%u.%u.%u.%u", a, b, c, d);
    return output;
}



void ipv6_to_str_unexpanded(char * str, const struct in6_addr * addr) {
   sprintf(str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 (int)addr->s6_addr[0], (int)addr->s6_addr[1],
                 (int)addr->s6_addr[2], (int)addr->s6_addr[3],
                 (int)addr->s6_addr[4], (int)addr->s6_addr[5],
                 (int)addr->s6_addr[6], (int)addr->s6_addr[7],
                 (int)addr->s6_addr[8], (int)addr->s6_addr[9],
                 (int)addr->s6_addr[10], (int)addr->s6_addr[11],
                 (int)addr->s6_addr[12], (int)addr->s6_addr[13],
                 (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
}
