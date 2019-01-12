all : compile

compile: main.o
	g++ -g -o dot11_pcap main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f dot11_pcap
	rm -f *.o

