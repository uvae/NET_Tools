#include <pcap.h>
#include <stdio.h>

void print_packet(const unsigned char* fpacket, const char* format, int sp, int ep, int convert=16, const char* format2=" ") {
  int output=0, i, c=0;
  printf("%s : ", format);
  if(sp>ep) { return; }
  for(sp; sp<=ep; sp++) {
	if(sp==ep) format2 = "";
  	if(convert==16) printf("%02x%s", fpacket[sp], format2);
	else if(convert==10) printf("%d%s", fpacket[sp], format2);
	else if(convert==1610) {
	  for(i=ep; i>=sp; i--) {
             int tc, to=1;
             for(tc=0; tc<c; tc++) { to*=256; }
	     output += (int)fpacket[i] * to;
	     c++;
	  }
	  printf("%d\n", output);
	  return;
	}
  }
  printf("\n");
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  printf("Start Intercept Packet!\n-------------------------------------------------\n");

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    int plen = 0, mlen = 0;

    if(packet[12] != 0x08 || packet[13] != 0x00) continue;
    
    for(plen; plen<header->caplen; plen++){
	if(plen % 8 == 0 && plen != 0) { printf("  "); }
	if(plen % 16 == 0 && plen != 0) { printf("\n"); }
	printf("%02x ", packet[plen]);
	if(plen > 70) {
	    printf("  ......\n");
     	    break;	    
	}
    }
    printf("\n>>> END Packet Hex Code\n\n");
    print_packet(packet, "ETH.smac", 6, 11, 16, ".");
    print_packet(packet, "ETH.dmac", 0, 5, 16, ".");
    print_packet(packet, "Type", 12, 13);
    print_packet(packet, "IP.sip", 26, 29, 10, ".");
    print_packet(packet, "IP.dip", 30, 33, 10, ".");
    print_packet(packet, "IP.sport", 34, 35, 1610);
    print_packet(packet, "IP.dport", 36, 37, 1610);
    if(header->caplen > 70) mlen = 70;
    else mlen = header->caplen;
    print_packet(packet, "Data", 55, mlen);
    printf("Packet Length : %d\n", header->caplen);
    

    printf(">>> END Packet :)\n");
    printf("\n-------------------------------------------------\n");
  }

  pcap_close(handle);
  return 0;
}
