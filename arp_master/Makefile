all : arp_master

arp_master: main.o
	g++ -g -o arp_master main.o -lpcap -lpthread

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f arp_master
	rm -f *.o

