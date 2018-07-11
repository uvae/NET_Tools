all: sum_test

main.o: main.cpp sum.h
	g++ -c main.cpp -o main.o

sum.o: sum.cpp sum.h
	g++ -c sum.cpp -o sum.o

sum_test: main.o sum.o
	g++ -o sum_test main.o sum.o

clean:
	rm -f *.o
	rm -f sum_test


