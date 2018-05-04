all : Netfilter_test

Netfilter_test : main.o
	g++ -g -std=c++14 -o Netfilter_test main.o -lnetfilter_queue

main.o : psy_header.h
	g++ -g -c -std=c++14 -o main.o main.cpp

clean :
	rm -f *.o Netfilter_test

