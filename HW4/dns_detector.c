#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <string.h>
#include <libnet.h>
#include <unistd.h>
#include <sys/param.h>
#include <resolv.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <stdint.h>

char ips[200][20]; 
char hosts[200][100];
int total_responses = 0;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

#define IP_MAX_LENGTH 16

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_int th_sport;               /* source port */
        u_int th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* UDP Header */
struct sniff_udp {
	u_short ud_sport; //source port
	u_short ud_dport; //destination port
	u_short ud_len; //Datagram Length
	u_short ud_sum; //Datagram checksum
};

//ICMP Header
struct sniff_icmp {
	unsigned char ic_type; //icmp type
	unsigned char ic_code; //icmp code
	unsigned short ic_sum; //icmp type
};

//ARP Packet
struct sniff_arp {
	u_short arp_htype; //arp hardware type
	u_short arp_ptype; //arp protocol type
	u_char arp_hlen; //Hardware address length
	u_char arp_plen; //Protocol Address Length
	u_short arp_operation; //ARP Operation
	u_char arp_sha[6]; //Sender hardware address
	u_char arp_spa[4]; //Sender protocol address
	u_char arp_tha[6]; //Target hardware address
	u_char arp_tpa[4]; //Target protocol address
};

//http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
//DNS header structure
struct DNS_HEADER
{
    unsigned    id:      16; // identification number
    unsigned    rd:       1; // recursion desired
    unsigned    tc:       1; // truncated message
    unsigned    aa:       1; // authoritive answer
    unsigned    opcode:   4; // purpose of message
    unsigned    qr:       1; // query/response flag
    
    unsigned    rcode:    4; // response code
    unsigned    cd:       1; // checking disabled
    unsigned    ad:       1; // authenticated data
    unsigned    unused:   1; // its z! reserved
    unsigned    ra:       1; // recursion available
    
    unsigned    qd_count: 16; // number of question entries
    unsigned    ans_count: 16; // number of answer entries
    unsigned    ns_count: 16; // number of authority entries
    unsigned    ar_count: 16; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
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

struct DNS_RESPONSE{
    int t_id;
    char domain[MAXHOSTNAMELEN];
    char answers[25][16];
    int num_answers;
};

char *interface = NULL;
struct DNS_RESPONSE dns_responses[500];

// http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets
u_char* readName(unsigned char* reader,unsigned char* buffer,int* count) {
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*) malloc(256);
 
    name[0]='\0';
 
    while(*reader!=0) {
        if(*reader>=192) {
            offset = (*reader) * 256 + *(reader+1) - 49152;
            reader = buffer + offset - 1;
            jumped = 1;
        }
        else {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0) {
            *count = *count + 1;
        }
    }
 
    name[p]='\0';
    if(jumped==1) {
        *count = *count + 1;
    }
 
    for(i=0;i<(int)strlen((const char*)name);i++) {
        p=name[i];
        for(j=0;j<(int)p;j++) {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0';
    return name;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	int attacked = 0;
	struct libnet_ipv4_hdr *ip;
	struct libnet_udp_hdr *udp;
	ip = (struct libnet_ipv4_hdr *)(packet + SIZE_ETHERNET);
		
	if (ip->ip_p != IPPROTO_UDP)
	{
		return;
	}
	
	udp = (struct libnet_udp_hdr *)(packet + SIZE_ETHERNET + LIBNET_IPV4_H);
	if (ntohs(udp->uh_sport) != 53) 
	{
		return;
	}

	struct DNS_HEADER *dns_hdr;
	char *dns_content;
	dns_hdr = (struct DNS_HEADER *) (packet + SIZE_ETHERNET + LIBNET_IPV4_H + LIBNET_UDP_H);
	dns_content = (char*) (packet + SIZE_ETHERNET + LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H);
	
	int dns_content_size = strlen(dns_content);
	
	char domain[MAXHOSTNAMELEN];	
	//u_char* pktend = (u_char *)packet + header->caplen;
	//int i = dn_expand((u_char *)dns_hdr, pktend, dns_content, domain, sizeof(domain));
	if ((dn_expand((u_char *)dns_hdr, (u_char *)(packet + (int)(header->caplen)), (u_char *)dns_content, domain, sizeof(domain)))<0)
	{
		fprintf(stderr, "Cannot expand domain name\n");
		return;
	}
	
	int dns_type = ((int)(*(dns_content+dns_content_size+2)));
	
	/*if (dns_type != T_A) 
	{
		cout<<"DNS Query not of type A - ignored"<<endl;
		return;
	}*/
	
	// https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
	// http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
	
	unsigned char *buf = (unsigned char *) (packet + SIZE_ETHERNET + LIBNET_IPV4_H + LIBNET_UDP_H);
	unsigned char *reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)dns_content)+1) + sizeof(struct QUESTION)];
	struct RES_RECORD answers[25];
	

	int stop = 0;
	int i, j;
	struct sockaddr_in a;	
	int counter = 0;
    int atypes = 0;
    int m = (ntohs(dns_hdr->ans_count));
    if(m>25)
    {
		m = 25;
	}
	for (i = 0; i < m; i++) {
		answers[counter].name=readName(reader,buf,&stop);
        reader = reader + stop;
 
        answers[counter].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);
 
        if(ntohs(answers[counter].resource->type) == T_A) { 
            atypes = 1;
            answers[counter].rdata = (unsigned char*) malloc(ntohs(answers[counter].resource->data_len));
            for(j=0 ; j<ntohs(answers[counter].resource->data_len) ; j++) 
            {
                answers[counter].rdata[j]=reader[j];
            }
            answers[counter].rdata[ntohs(answers[counter].resource->data_len)] = '\0';
            reader = reader + ntohs(answers[counter].resource->data_len);
            counter++;
        } 
        else 
        {
            answers[counter].rdata = readName(reader,buf,&stop);
            reader = reader + stop;
            counter++;
        }
	}
	
	if(atypes == 0)
	{
		printf("No A type responses detected...\n");
		return;
	}
	
	for(i = 0; i < total_responses; i++) 
	{
        if(dns_responses[i].t_id == (int) dns_hdr->id) 
        { 
			if(strcmp(dns_responses[i].domain, domain) == 0)
			{
				//checking for loopback problems				
				int check = 0;				
				int q;
				for (q = 0; q < dns_responses[i].num_answers; q++) {
					int w;
					for (w = 0; w < ntohs(dns_hdr->ans_count); w++) {
						if (ntohs(answers[w].resource->type) == T_A) {
							struct sockaddr_in addr;
							long *p;
							p=(long*)answers[w].rdata;
							addr.sin_addr.s_addr=(*p);
							if (strcmp(dns_responses[i].answers[q], inet_ntoa(addr.sin_addr)) == 0) {
								check = 1;
							}
						}
					}
				}
				
				if(check == 0)
				{
					attacked = 1;
					break;
				}
            }
        }
    }
    
    if (attacked == 1) 
    {
		char cur_time[100];
		char final_time[100];
		time_t time = (time_t)header->ts.tv_sec;
		strftime(cur_time, 20, "%Y-%m-%d %H:%M:%S", localtime(&time));
		snprintf(final_time, sizeof final_time, "%s.%06d", cur_time, (time_t)header->ts.tv_usec);
				
        printf("%s DNS poisoning attempt\n", final_time);
        printf("TXID %d Request %s\n", (int) dns_hdr->id, domain);
        printf("Answer1 [");
        for (j = 0; j < dns_responses[i].num_answers; j++)
        {
            printf("%s - ", dns_responses[i].answers[j]);
		}
        printf("]\n");

        printf("Answer2 [");
        for (j = 0; j < ntohs(dns_hdr->ans_count); j++) 
        {
            if( ntohs(answers[j].resource->type) == T_A) 
            {
                long *p;
                p=(long*)answers[j].rdata;
                a.sin_addr.s_addr=(*p);
                printf("%s - ", inet_ntoa(a.sin_addr));
            }
        }
        printf("]\n\n");
    }
    else {       
        if (atypes == 1) {
            dns_responses[total_responses].t_id = (int) dns_hdr->id;
            dns_responses[total_responses].num_answers = 0;
            strcpy(dns_responses[total_responses].domain, domain);
            
            int m2 = (ntohs(dns_hdr->ans_count));
            if(m2 > 25)
            {
				m2 = 25;
			}
            for(j = 0 ; j < m2; j++) {
                if( ntohs(answers[j].resource->type) == T_A) 
                { 
                    long *p;
                    p=(long*)answers[j].rdata;
                    a.sin_addr.s_addr=(*p);
                    strncpy(dns_responses[total_responses].answers[dns_responses[total_responses].num_answers], inet_ntoa(a.sin_addr), IP_MAX_LENGTH);
                    dns_responses[total_responses].num_answers++;
                }           
            }
            total_responses++;
        }
    }	
}

int main(int argc, char *argv[])
{
	int option = 0;
	char* file_name = NULL;
	
	//program name
	int num_args = 0;
	
	int file_present = 0;
	
	while ((option = getopt(argc, argv, "i:r:")) != -1) {
		switch(option) {
			case 'i':
				interface = optarg;
				num_args+=2;
				break;
			case 'r':
				file_present = 1;
				file_name = optarg;
				num_args+=2;
				break;
			case '?':
				if(optopt == 'i')
				{
					fprintf(stderr, "No interface provided");
					return(-2);
				}
				else if(optopt == 'r')
				{
					fprintf(stderr, "No file specified");
					return(-2);
				}
				else
				{
					fprintf(stderr, "Invalid argument");
					return(-2);
				}
			default:
				fprintf(stderr, "Unknown Error");
				return(-2);
		}
	}
	
	char filter_exp[100];
	int i;
	if((num_args+1) < argc)
	{
		for(i=num_args;i<argc;i++)
		{
			strcpy(filter_exp, argv[i]);
			int j;
			for(j=i+1;j<argc;j++)
			{
				strcat(filter_exp, " ");
				strcat(filter_exp, argv[j]);
			}
		}
	}
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	
	if(file_present == 1)
	{
		handle = pcap_open_offline(file_name, errbuf);
		if(handle == NULL)
		{
			fprintf(stderr, "Error in reading the file : %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}
	else
	{
		if(!interface)
		{
			interface = pcap_lookupdev(errbuf);
			if (interface == NULL) {
				fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
				return (-2);
			}
			printf("Using default interface\n");
		}
		/* open capture device */
		handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
			exit(EXIT_FAILURE);
		}
		/* make sure we're capturing on an Ethernet device [2] */
		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", interface);
			exit(EXIT_FAILURE);
		}
		
	}
	if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) 
		{
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n", interface, errbuf);
			net = 0;
			mask = 0;
			exit(EXIT_FAILURE);
		}
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
		{
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
		/* apply the compiled filter */
		if (pcap_setfilter(handle, &fp) == -1) 
		{
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
		//printf("%s", filter_exp);
		
		pcap_loop(handle, -1, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	
	return 0;
	
}
