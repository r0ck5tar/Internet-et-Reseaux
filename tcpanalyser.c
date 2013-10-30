/*
 * This is a TCP packet analyser that uses libpcap to read .pcap files dumped 
 * using Tcpdump or Wireshark.
 *
 * To compile, use the -lpcap switch:
 * gcc -Wall -o tcpanalyser tcpanalyser.c -lpcap
 */
#define SIZE_ETHERNET 14

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/tcp.h>

int main (int argc, char *argv[]){
  char errbuff[PCAP_ERRBUF_SIZE];

  if(argc != 2) {
    printf("Provide a path to a .pcap file:\n%s filename", argv[0]);
    exit(1);
  }

  if(pcap_open_offline(argv[1], errbuff) != NULL) {
    printf("Success! .pcap file can be opened!\n");
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct pcap_pkthdr header; // The header that pcap gives us 
    const u_char *packet; // The actual packet 

    handle = pcap_open_offline(argv[1], errbuff);

    int count = 0;
   
    const struct ip *ip;              /* The IP header */
    uint size_ip;
    uint ip_len;

    const struct tcphdr *tcp;            /* The TCP header */
    uint size_tcp;

    uint packet_len;

    while((packet = pcap_next(handle, &header))) {
      count++;
      ip = (struct ip*)(packet + SIZE_ETHERNET);
      size_ip = 4*ip->ip_hl;
      ip_len = ntohs(ip->ip_len);
      
      printf("\n\nPacket length:\t\t%u bytes\n", ip_len);
      printf("IP header length: \t%u bytes\n", size_ip);

      tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
      size_tcp = 4*tcp->doff;
      printf("TCP header length: \t%u bytes\n", size_tcp);

      printf("Data length: \t\t%u bytes\n", (ip_len - size_ip - size_tcp));

      printf("SEQ: \t\t\t%x\n",ntohl(tcp->seq));
      printf("ACK: \t\t\t%x\n",ntohl(tcp->ack_seq));

    }

      printf("\n\ntotal packets : %u\n", count); 
  }
  else{
    printf("%s\n", errbuff);
  }

  return 0;
}
