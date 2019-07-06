#include <iostream>
#include <pcap.h>

#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define LINE_LEN 16

using namespace std;

int main()
{
  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the pcap file.
  pcap_t *handle = pcap_open_offline("example.pcap", errbuf);
  if (handle == nullptr)
  {
    std::cerr << "Failed to open pcap file: " << errbuf << std::endl;
    exit(1);
  }

  int count = 0;

  while (true)
  {
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    struct pcap_pkthdr *header;
    const u_char *buffer;

    // Fetch the first packet into header and buffer.
    // If there are no more packets, leave the loop.
    int status = pcap_next_ex(handle, &header, &buffer);
    if (status != 1)
    {
      break;
    }

    // Parse from the raw packet buffer the following information:
    // - The source IP address
    // - The destination IP address
    // - If the protocol is TCP or UDP:
    //     - The source port
    //     - The destination port

    // Timestamp, in human readable format (HH:MM:SS, microseconds)
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
    printf("Timestamp: %s, %.6d\nLength: %d\n", timestr, header->ts.tv_usec, header->len);

    // Retreive Source/Dest. IP Address
    struct ip *ip;

    ip = (struct ip *)(buffer + sizeof(struct ether_header));
    char *src = inet_ntoa(ip->ip_src);
    char *dst = inet_ntoa(ip->ip_dst);

    cout << "Source IP Address: " << src << endl;
    cout << "Destination IP Address: " << dst << endl;

    // Detect Protocol Type
    switch (ip->ip_p)
    {
    case IPPROTO_TCP:
      // If TCP, check header for source and dest. port
      printf("Protocol: TCP\n");
      struct tcphdr *tcp;
      tcp = (struct tcphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct ip));

      cout << "Source Port: " << tcp->th_sport << endl;
      cout << "Destination Port: " << tcp->th_dport << endl;
      break;
    case IPPROTO_UDP:
      // If UDP, check header for source and dest. port
      printf("Protocol: UDP\n");
      struct udphdr *udp;
      udp = (struct udphdr *)(buffer + sizeof(struct ether_header) + sizeof(struct ip));

      cout << "Source Port: " << udp->uh_sport << endl;
      cout << "Destination Port: " << udp->uh_dport << endl;
      break;
    case IPPROTO_ICMP:
      printf("Protocol: ICMP\n");
      break;
    default:
      printf("Protocol: Unknown\n");
      break;
    }

    // Display Packet Data in Hexadecimal Format
    cout << "Data:" << endl;
    for (int i = 1; (i < header->len + 1); i++)
    {
      printf("%.2x ", buffer[i - 1]);
      if ((i % LINE_LEN) == 0)
        cout << endl;
    }

    cout << endl
         << endl;
  }

  // Finish the pcap session.
  pcap_close(handle);
}
