#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <iostream>

using namespace std;

int string_search;
string myStr;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

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

/*
The pcap_pkthdr as defined in the source code

00126 struct pcap_pkthdr {
00127     struct timeval ts;
00128     bpf_u_int32 caplen;
00129     bpf_u_int32 len;
00130 };

*/

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset);

int check_string_presence(const u_char *payload, int len);

int check_string_presence(const u_char *payload, int len)
{
	const u_char *ch = payload;
	int num_chars = len;
	int i;
	char* str_payload = new char[num_chars+1];
	for(i=0;i<num_chars;i++)
	{
		if (isprint(*ch))
		{
			str_payload[i] = (char)(*ch);
		}
		else
		{
			str_payload[i] = '.';
		}
		ch++;
	}
	str_payload[i] = '\0';

	string tempstr = str_payload;
	if((tempstr.find(myStr)) != std::string::npos)
	{
		free(str_payload);
		return 1;
	}
	free(str_payload);

	return 0;

}

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */


	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_tcp *tcp1;            /* The TCP header */
	const struct sniff_udp *udp;            /* The UDP header */
	const struct sniff_udp *udp1;            /* The UDP header */
	const struct sniff_icmp *icmp;            /* The ICMP header */
	u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_udp;
	int size_tcp1;
	int size_udp1;
	int size_icmp;
	int size_payload;
	const char* compstr = myStr.c_str();

	const u_char* eth_info;

	struct tm* tm_info;
	char *time_cur=new char[100];
	char *buf=new char[100];
	long int milli;
	int i;

	count++;

	int t=0, u=0, ic=0, ot =0;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/*
	Check for an arp packet before moving on to other packet types
	If found just return from the function after printing details
	*/
	const struct sniff_arp *arp;
	u_short e_type = ntohs(ethernet->ether_type);
	char str_e_type[30];
	sprintf(str_e_type,"%x", e_type);

	if(strcmp(str_e_type,"806") == 0)
	{
		if(string_search == 1)
		{
			//No need to print anything
			return;
		}
		arp = (struct sniff_arp*)(packet + SIZE_ETHERNET);
		//get time for the packet received
		tm_info = localtime (&header->ts.tv_sec);
		strftime(time_cur, sizeof time_cur, "%Y-%m-%d %H:%M:%S", tm_info);
		snprintf(buf, sizeof buf, "%s.%06ld", time_cur, &header->ts.tv_usec);

		//get milliseconds
		milli = ((long int)&header->ts.tv_usec)/1000;

		printf("%s.%ld ",time_cur, milli);

		eth_info = ethernet->ether_shost;
		i = ETHER_ADDR_LEN;
		while(i>0)
		{

			char temp1[3];
			sprintf(temp1, "%x", *eth_info++);
			if(strlen(temp1) ==1)
			{
				temp1[1] = temp1[0];
				temp1[0] = '0';
				temp1[2] = '\0';
			}
			if(i==ETHER_ADDR_LEN)
			{
				printf("%s", temp1);
			}
			else
			{
				printf("%s%s",":", temp1);
			}
			i--;
		}

		printf(" -> ");

		eth_info = ethernet->ether_dhost;
		i = ETHER_ADDR_LEN;
		while(i>0)
		{

			char temp1[3];
			sprintf(temp1, "%x", *eth_info++);
			if(strlen(temp1) ==1)
			{
				temp1[1] = temp1[0];
				temp1[0] = '0';
				temp1[2] = '\0';
			}
			if(i==ETHER_ADDR_LEN)
			{
				printf("%s", temp1);
			}
			else
			{
				printf("%s%s",":", temp1);
			}
			i--;
		}

		printf(" type 0x%x\n", ntohs(ethernet->ether_type));

		if(ntohs(arp->arp_operation) == 1)
		{
			printf("ARP Request - ");

		}
		if(ntohs(arp->arp_operation) == 2)
		{
			printf("ARP Reply - ");

		}
		printf("Sender : %d.%d.%d.%d, ", arp->arp_spa[0],arp->arp_spa[1],arp->arp_spa[2],arp->arp_spa[3]);
		printf("Target : %d.%d.%d.%d\n", arp->arp_tpa[0],arp->arp_tpa[1],arp->arp_tpa[2],arp->arp_tpa[3]);

		return;
	}


	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	//if there is a string to be searched, check if present in a tcp or udp packet
	if(string_search==1)
	{
		if(ip->ip_p == IPPROTO_TCP)
		{
			t =1;
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}

			try{

			/* define/compute tcp payload (segment) offset */
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
            const u_char *ch = payload;
            int num_chars = size_payload;
			char *str_payload=new char[1000000];
			if(!str_payload)
			{
                return;
			}
            for(i=0;i<num_chars;i++)
            {
                if (isprint(*ch))
                {
                    str_payload[i] = (char)(*ch);
                }
                else
                {
                    str_payload[i] = '.';
                }
                ch++;
            }
            str_payload[i] = '\0';

			if((memmem(str_payload, strlen(str_payload), compstr, strlen(compstr))) == NULL)
			{
				//String not found
				return;
			}
			}
			catch(std::exception ba)
			{
                std::cerr << "Bad allocation, packet corrupted: " <<ba.what()<<"\n";
                return;
			}
		}
		else if(ip->ip_p == IPPROTO_UDP)
		{
			u=1;
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
			/* define/compute udp payload (segment) offset */
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8);
			/* compute udp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + 8);
			if((memmem(payload, size_payload, compstr, strlen(compstr))) == NULL)
			{
				//String not found
				return;
			}
		}
		else
		{
			return;
		}
	}

	/* get source and destination IP addresses */
	char ips[30],ipd[30];
	sprintf(ips, "%s", inet_ntoa(ip->ip_src));
	sprintf(ipd, "%s", inet_ntoa(ip->ip_dst));

	//get time for the packet received
	tm_info = localtime (&header->ts.tv_sec);
	strftime(time_cur, sizeof time_cur, "%Y-%m-%d %H:%M:%S", tm_info);
	snprintf(buf, sizeof buf, "%s.%06ld", time_cur, &header->ts.tv_usec);

	//get milliseconds
	milli = ((long int)&header->ts.tv_usec)/1000;

	printf("%s.%ld ",time_cur, milli);

	eth_info = ethernet->ether_shost;
	i = ETHER_ADDR_LEN;
	while(i>0)
	{

		char temp1[3];
		sprintf(temp1, "%x", *eth_info++);
		if(strlen(temp1) ==1)
		{
			temp1[1] = temp1[0];
			temp1[0] = '0';
			temp1[2] = '\0';
		}
		if(i==ETHER_ADDR_LEN)
		{
			printf("%s", temp1);
		}
		else
		{
			printf("%s%s",":", temp1);
		}
		i--;
	}

	printf(" -> ");

	eth_info = ethernet->ether_dhost;
	i = ETHER_ADDR_LEN;
	while(i>0)
	{

		char temp1[3];
		sprintf(temp1, "%x", *eth_info++);
		if(strlen(temp1) ==1)
		{
			temp1[1] = temp1[0];
			temp1[0] = '0';
			temp1[2] = '\0';
		}
		if(i==ETHER_ADDR_LEN)
		{
			printf("%s", temp1);
		}
		else
		{
			printf("%s%s",":", temp1);
		}
		i--;
	}

	printf(" type 0x%x", ntohs(ethernet->ether_type));

	printf(" ");

	int cur_case = -1;

	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
		if(t!=1){
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}
			/* define/compute tcp payload (segment) offset */
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
			if(size_payload<0){
				size_payload = 0;
				break;
			}
		}
			printf("len %d\n", size_payload);
			printf("%s:%d -> %s:%d TCP\n", ips, ntohs(tcp->th_sport), ipd, ntohs(tcp->th_dport));
			cur_case = 0;
			break;
		case IPPROTO_UDP:
		if(u!=1){
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
			/* define/compute udp payload (segment) offset */
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8);
			/* compute udp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + 8);
		}
			printf("len %d\n", size_payload);
			printf("%s:%d -> %s:%d UDP\n", ips, ntohs(udp->ud_sport), ipd, ntohs(udp->ud_dport));
			cur_case = 1;
			break;
		case IPPROTO_ICMP:
		if(ic!=1) {
			icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip + 8);
			/* define/compute icmp payload (segment) offset */
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + 8);
			/* compute icmp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + 8);
		}
			printf("   Protocol: ICMP\n");
			printf("%s -> %s ICMP\n", ips, ipd);
			cur_case = 2;
			break;
		default:
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
			/* compute icmp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip);
			//Print the entire payload as is
			printf("   Protocol: Other\n");

			break;
	}


	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		print_payload(payload, size_payload);
	}

return;
}



int main(int argc, char *argv[])
{
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[100];		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */

	int started=0;

	//in case of both -i and -r, use the one which is encountered first
	//check number of arguments
	int i;

	char match_str1[100];
	int string_search1=0;

	for(i=1;i<argc;i++) {
		if(strcmp(argv[i],"-s") == 0)
		{

			//The user wants to check for the presence of a string
			if((i+1)==argc)
			{
				printf("Incorrect format");
				exit(EXIT_FAILURE);
			}
			strcpy(match_str1, argv[i+1]);
			string_search1 = 1;
			myStr = match_str1;
		}
		if(strcmp(argv[i],"-i") == 0)
		{
			//ignore if an option was already determined
			if(started==1) {
				continue;
			}
			//the user wants to specify a live interface
			/* open capture device */
			if((i+1)==argc)
			{
				printf("Incorrect format");
				exit(EXIT_FAILURE);
			}
			handle = pcap_open_live(argv[i+1], SNAP_LEN, 1, 1000, errbuf);
			if (handle == NULL) {
				fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
				exit(EXIT_FAILURE);
			}
			/* get network number and mask associated with capture device */
			if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
				fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
				    dev, errbuf);
				net = 0;
				mask = 0;
			}
			started = 1;
		}
		if(strcmp(argv[i],"-r") == 0)
		{
			//ignore if an option was already determined
			if(started==1) {
				continue;
			}
			//the user wants to specify a live interface
			//open file for capture
			if((i+1)==argc)
			{
				printf("Incorrect format");
				exit(EXIT_FAILURE);
			}
			handle = pcap_open_offline(argv[i+1], errbuf);
			if (handle == NULL) {
				fprintf(stderr, "Couldn't read file %s\n", errbuf);
				exit(EXIT_FAILURE);
			}
			started = 1;
		}
	}

	string_search = string_search1;

	if(started == 0)
	{
		//Nothing specified, go for the default
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
		/* open capture device */
		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(EXIT_FAILURE);
		}
		/* make sure we're capturing on an Ethernet device [2] */
		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", dev);
			exit(EXIT_FAILURE);
		}
		/* get network number and mask associated with capture device */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}
	}

	//get the filters once everything else is initialized
	for(i=1;i<argc;i++)
	{
		if((strcmp(argv[i-1], "-i")!=0) && (strcmp(argv[i-1], "-r")!=0) && (strcmp(argv[i-1], "-s")!=0) &&(strcmp(argv[i], "-i")!=0) && (strcmp(argv[i], "-r")!=0) && (strcmp(argv[i], "-s")!=0))
		{
			//current i
			int j;
			//we assume that all strings after this position are part of the BPF filter
			strcpy(filter_exp, argv[i]);
			for(j=i+1;j<argc;j++)
			{
				strcat(filter_exp, " ");
				strcat(filter_exp, argv[j]);
			}
			/* compile the filter expression */
			if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n",
				    filter_exp, pcap_geterr(handle));
				exit(EXIT_FAILURE);
			}
			/* apply the compiled filter */
			if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Couldn't install filter %s: %s\n",
				    filter_exp, pcap_geterr(handle));
				exit(EXIT_FAILURE);
			}
			printf("%s", filter_exp);
			break;
		}

	}

	/* now we can set our callback function */

	pcap_loop(handle, -1, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

	return 0;

}
