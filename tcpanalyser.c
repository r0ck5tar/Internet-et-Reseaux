/*
 * This is a TCP packet analyser that uses libpcap to read .pcap files dumped 
 * using Tcpdump or Wireshark.
 *
 * To compile, use the -lpcap switch:
 * gcc -Wall -o tcpanalyser tcpanalyser.c -lpcap
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

int main (int argc, char *argv[]){
  char errbuff[PCAP_ERRBUF_SIZE];

  if(argc != 2) {
    printf("Provide a path to a .pcap file:\n%s filename", argv[0]);
    exit(1);
  }

  if(pcap_open_offline(argv[1], errbuff) != NULL) {
    printf("Success! .pcap file can be opened!\n");
  }
  else{
    printf("%s\n", errbuff);
  }
  
  return 0;
}
