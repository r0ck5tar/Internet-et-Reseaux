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
#include <string.h>
#include <stdbool.h>
#include <linux/tcp.h>

char server_ip[15] = "";
int late_packets = 0;
char errbuff[PCAP_ERRBUF_SIZE];
char file[15] = "";
char*  determine_server_ip();
void parse_packet(const u_char *packet, int count);
FILE *f;

int main (int argc, char *argv[]){
  pcap_t *handle;
  f = fopen("resultat.csv","w");
  fprintf(f,"Packet number,SEQ,delay\n");
  fclose(f);

  if(argc != 2) {
    printf("Provide a path to a .pcap file:\n%s filename", argv[0]);
    exit(1);
  }

  if((handle = pcap_open_offline(argv[1], errbuff)) != NULL) {
    strcpy(file, argv[1]);

    struct pcap_pkthdr header; // The header that pcap gives us 
    const u_char *packet; // The actual packet 
    int count = 0;

    strcpy(server_ip, determine_server_ip());

    while((packet = pcap_next(handle, &header))) {
      count++;
      parse_packet(packet, count);
    }

    printf("\n\ntotal packets : %d\nlate packets : %d\n\n", count, late_packets); 
  }
  else{
    printf("%s\n", errbuff);
  }

  return 0;
}

char*  determine_server_ip() {
  int count = 0;
  pcap_t *handle;
  handle = pcap_open_offline(file, errbuff);
  const u_char *packet;
  struct pcap_pkthdr header;

  const struct ip *ip;              /* The IP header */

  while(count<3){
    packet = pcap_next(handle, &header);

    ip = (struct ip*)(packet + SIZE_ETHERNET);
    
    if(ip->ip_p==IPPROTO_TCP) {
      return inet_ntoa(ip->ip_dst);
    }
    count++;
  }  
  
  return 0;
}

void parse_packet(const u_char *packet, int count) {
  const struct ip *ip;              /* The IP header */
  uint size_ip;
  uint ip_len;

  const struct tcphdr *tcp;            /* The TCP header */
  uint size_tcp;

  static uint next_seq = 0;
  static uint old_seq = 0;
  static uint old_seq_expected = 0;

  ip = (struct ip*)(packet + SIZE_ETHERNET);

  if(strcmp(server_ip, inet_ntoa(ip->ip_src))==0){
    size_ip = 4*ip->ip_hl;
    ip_len = ntohs(ip->ip_len);
    tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = 4*tcp->doff;

    if(ntohl(tcp->seq) == next_seq)  {
      //printf("\nPacket %05d on time\n", count);
      //printf("expected SEQ: \t\t%x\n",next_seq);
      //printf("actual SEQ: \t\t%x\n", ntohl(tcp->seq));
    }

    else if (ntohl(tcp->seq) > next_seq){;
      old_seq = next_seq;
      old_seq_expected = count;
    }

    else if(ntohl(tcp->seq) == old_seq) {
      late_packets++;
      f = fopen("resultat.csv","a");
      fprintf(f, "%d,%x,%d\n", count, ntohl(tcp->seq), count-old_seq_expected);
      fclose(f);

      old_seq=0;
    } 

    else {
      
      late_packets++;
      f = fopen("resultat.csv","a");
      fprintf(f, "%d,%x,%d\n", count, ntohl(tcp->seq), count-old_seq_expected);
      fclose(f);
    
      old_seq=next_seq;      
    }

    if ((ip_len - size_ip - size_tcp)==0) {
      next_seq = ntohl(tcp->seq)+1;
    }
    else{
      next_seq = ntohl(tcp->seq)+ip_len - size_ip - size_tcp;
    }
  }
}

