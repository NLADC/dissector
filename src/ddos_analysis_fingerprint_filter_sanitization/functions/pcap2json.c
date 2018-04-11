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
    
    unsigned char qclass :1;
    unsigned short temp;
    unsigned short qtype;
};

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
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count);


FILE *jsonfile;
char *json_string;
struct json_object *jobj, *jobj_ether, *jobj_ip, *jobj_tcp, *jobj_udp, *jobj_icmp, *jobj_dns;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;

//#define JSON_C_TO_STRING_NOSLASHESCAPE (1<<4)
#define T_A 1 //Ipv4 address

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
    jobj_dns = json_object_new_object();

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

    fprintf(jsonfile,"%s\n", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_NOSLASHESCAPE | JSON_C_TO_STRING_PLAIN));
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

    //sprintf(json_string, "%s", json_object_to_json_string_ext(jobj_ether, JSON_C_TO_STRING_NOSLASHESCAPE));
    json_object_object_add(jobj, "ether", json_object_get(jobj_ether));
    return;
}

void print_ip_header(const u_char * Buffer, int Size)
{
    //print_ethernet_header(Buffer , Size);

    //unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    //iphdrlen =iph->ihl*4;

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

    //int fragment_offset = iph->frag_off;
    //printf("Fragment offset: %d", fragment_offset);
    //if (fragment_offset == 32) {
    //  printf("Is fragment\n\n");
    //}

    sprintf(temp, "%d",((int)(iph->frag_off) == 32) ? 1 : 0);
    json_object_object_add(jobj_ip, "is_fragmented", json_object_new_string(temp));
    sprintf(temp, "%d",(unsigned int)iph->ttl);
    json_object_object_add(jobj_ip, "ttl", json_object_new_string(temp));
    //sprintf(temp, "%d",(unsigned int)iph->protocol);
    //json_object_object_add(jobj_ip, "proto", json_object_new_string(temp));
    sprintf(temp, "%d", (unsigned int)iph->protocol);
    json_object_object_add(jobj,"ip_proto", json_object_new_string(temp));


    //printf("Don't fragment: %x\n", ((ntohs(iph->frag_off)):1));
    //printf("More fragments: %x\n\n", ((ntohs(iph->frag_off)):1));


    sprintf(temp, "%d", ntohs(iph->check));
    json_object_object_add(jobj_ip, "checksum", json_object_new_string(temp));
    //sprintf(temp, "%s" , inet_ntoa(source.sin_addr));
    //json_object_object_add(jobj_ip, "src", json_object_new_string(temp));
    //sprintf(temp, "%s" , inet_ntoa(dest.sin_addr));
    //json_object_object_add(jobj_ip, "dst", json_object_new_string(temp));
    sprintf(temp, "%s", inet_ntoa(source.sin_addr));
    json_object_object_add(jobj, "ip_src", json_object_new_string(temp));
    sprintf(temp, "%s", inet_ntoa(dest.sin_addr));
    json_object_object_add(jobj, "ip_dst", json_object_new_string(temp));

    free(temp);

    //sprintf(json_string, "%s", json_object_to_json_string_ext(jobj_ip, JSON_C_TO_STRING_NOSLASHESCAPE));
    json_object_object_add(jobj, "ip_header", json_object_get(jobj_ip));

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

    //sprintf(json_string, "%s", json_object_to_json_string_ext(jobj_tcp, JSON_C_TO_STRING_NOSLASHESCAPE));
    json_object_object_add(jobj, "transport_header", json_object_get(jobj_tcp));

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

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
    int sport = ntohs(udph->source);
    int dport = ntohs(udph->dest);

    print_ip_header(Buffer,Size);

    char *temp =(char*)malloc(sizeof(char)*50);
    // sprintf(temp, "%d" , sport);
    // json_object_object_add(jobj_udp, "sport", json_object_new_string(temp));
    // sprintf(temp, "%d" , dport);
    // json_object_object_add(jobj_udp, "dport", json_object_new_string(temp));
    sprintf(temp, "%d" , sport);
    json_object_object_add(jobj, "port_src", json_object_new_string(temp));
    sprintf(temp, "%d" , dport);
    json_object_object_add(jobj, "port_dst", json_object_new_string(temp));



    sprintf(temp, "%d" , ntohs(udph->len));
    json_object_object_add(jobj_udp, "len", json_object_new_string(temp));
    sprintf(temp,  "%d" , ntohs(udph->check));
    json_object_object_add(jobj_udp, "checksum", json_object_new_string(temp));
    free(temp);

    //sprintf(json_string, "%s", json_object_to_json_string_ext(jobj_udp, JSON_C_TO_STRING_NOSLASHESCAPE));
    json_object_object_add(jobj, "transport_header", json_object_get(jobj_udp));


    if (sport == 53 || dport == 53) {
      struct DNS_HEADER *dns = NULL;
      struct QUESTION *qinfo = NULL;

      //unsigned char buf[65536], *qname, *reader;
      //struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server

      //Set the DNS structure to standard queries
      dns = (struct DNS_HEADER*)(Buffer+header_size);

      /*printf("Transaction ID: 0x%x\n", ntohs(dns->id)); // Transaction ID
      printf("Query response flag: %x\n", dns->qr);
      printf("Opcode: %x\n", ntohs(dns->opcode));
      printf("Truncated message: %x\n", dns->tc);
      printf("Recursion desired: %x\n", dns->rd);
      printf("Z: %x\n", dns->z);
      printf("Non-authenticated data: %x\n", dns->ad);
      printf("Questions: %d\n", ntohs(dns->q_count));
      printf("Answer RRs: %d", ntohs(dns->ans_count));
      printf("Authority RRs: %d", ntohs(dns->auth_count));
      printf("Additional RRs: %d", ntohs(dns->add_count)); */

      char *temp3 =(char*)malloc(sizeof(char)*2000);
      sprintf(temp3, "0x%x" , ntohs(dns->id));
      json_object_object_add(jobj_dns, "id", json_object_new_string(temp3));
      sprintf(temp3, "%x" , ntohs(dns->qr));
      json_object_object_add(jobj_dns, "query_flag", json_object_new_string(temp3));
      sprintf(temp3, "0x%x" , ntohs(dns->opcode));
      json_object_object_add(jobj_dns, "opcode", json_object_new_string(temp3));
      sprintf(temp3,  "%x" , dns->tc);
      json_object_object_add(jobj_dns, "truncated", json_object_new_string(temp3));
      sprintf(temp3, "%x", dns->rd);
      json_object_object_add(jobj_dns, "recusion_desired", json_object_new_string(temp3));
      //sprintf(temp3, "%x", dns->z);
      //json_object_object_add(jobj_dns, "z", json_object_new_string(temp3));
      sprintf(temp3, "%x", dns->ad);
      json_object_object_add(jobj_dns, "non_auth_data", json_object_new_string(temp3));
      sprintf(temp3, "%d", ntohs(dns->q_count));
      json_object_object_add(jobj_dns, "questions", json_object_new_string(temp3));
      sprintf(temp3, "%d", ntohs(dns->ans_count));
      json_object_object_add(jobj_dns, "answers", json_object_new_string(temp3));
      sprintf(temp3, "%d", ntohs(dns->auth_count));
      json_object_object_add(jobj_dns, "authorities", json_object_new_string(temp3));
      sprintf(temp3, "%d", ntohs(dns->add_count));
      json_object_object_add(jobj_dns, "additional", json_object_new_string(temp3));

      
      //point to the query portion
      //dns = (struct DNS_HEADER*)(Buffer+header_size);
      unsigned char *qname =(unsigned char*)(Buffer+header_size+sizeof(struct DNS_HEADER) + 1);
      unsigned char *reader = (unsigned char*)(sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION));
      printf("Query name: %s\n", qname);
      printf("string length %d\n", strlen((const char*)qname));
      qinfo = (struct QUESTION*)(Buffer+header_size + sizeof(struct DNS_HEADER) + strlen((const char*)qname) + 1);
      
      //printf("query all: %x\n", qinfo->temp);
      printf("Query type: %x\n", (qinfo->qtype));
      printf("Query info: %x\n", (qinfo->qclass));
      //printf("z bit: %x\n", (qinfo->z));
      /*
      unsigned char buf[65536];
      //ChangetoDnsNameFormat(qname , host);
      
      qinfo = (struct QUESTION*)(Buffer+header_size+strlen(qname)); //fill it



      
      //qinfo->qtype = htons( query_type ); //type of the query , A , MX , CNAME , NS etc
      //qinfo->qclass = htons(1); //its internet (lol)
      */
      if (sport == 53) {
        /*printf("Recursion available: %x\n", dns->ra);
        printf("Authorative answer: %x\n", dns->aa);
        printf("Response code: %x\n", ntohs(dns->rcode));*/
        sprintf(temp3, "%x", dns->ra);
        json_object_object_add(jobj_dns, "recursion_available", json_object_new_string(temp3));
        sprintf(temp3, "%x", dns->aa);
        json_object_object_add(jobj_dns, "authorative_answer", json_object_new_string(temp3));
        sprintf(temp3, "0x%x", ntohs(dns->rcode));
        json_object_object_add(jobj_dns, "rcode", json_object_new_string(temp3));
       
      }

      free(temp3);
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
    json_object_object_add(jobj, "transport_header", json_object_get(jobj_icmp));

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

u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;

    *count = 1;
    name = (unsigned char*)malloc(256);

    name[0]='\0';

    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }

        reader = reader+1;

        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }

    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }

    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++)
    {
        p=name[i];
        for(j=0;j<(int)p;j++)
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}
