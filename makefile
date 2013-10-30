CC=gcc
CFLAGS=-lpcap

make: tcpanalyser.c
	$(CC) -Wall -o tcpanalyser tcpanalyser.c $(CFLAGS) 



