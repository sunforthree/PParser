#include "lpcap.h"

namespace sunfor3 {

/* internal variables. */
llhttp_cube_t* http_handle;
// error buffer define.
char errBuf[PCAP_ERRBUF_SIZE];
int err;

pcap_t* init_pcap(PcapType type, const char* location) {
  pcap_t* handle;
  /* Begin of pcap handle init. */
  if (type == ONLINE_TYPE) {
    printf("ONLINE MODE\n");
    handle = pcap_open_live(location, BUFSIZ, 1, 1000, errBuf);
    if (handle == NULL) {
      fprintf(stderr, "Couldn't open device %s: %s\n", location, errBuf);
      return NULL;
    }
  }
  else if (type == OFFLINE_TYPE) {
    printf("OFFLINE MODE\n");
    handle = pcap_open_offline(location, errBuf);
    if (handle == NULL) {
      fprintf(stderr, "Couldn't open file %s: %s\n", location, errBuf);
      return NULL;
    }
  }
  /* End of pcap handle init. */

  /* HTTP handle init. */
  http_handle = http_init();

  return handle;
}

void end_pcap(pcap_t* handle) {  
  if (handle != nullptr)
    pcap_close(handle);
  else {
    fprintf(stderr, "Handle was not init!\n");
    return;
  }
  http_end(http_handle);
}

void packet_process(pcap_t* handle, struct pkt_parser* parser, pcap_handler handler) {
  if (pcap_loop(handle, -1, handler, (u_char*)parser) < 0) {
    fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(handle));
    fprintf(stderr, "pcap_loop() failed: %s, errcode: %d\n", errBuf, err);
    exit(-1);
  }
}

void packet_handler(u_char* parser, const struct pcap_pkthdr* header, const u_char* pkt_data) {  
  struct pkt_parser* internal_parser = (struct pkt_parser*)parser;
  /* Clean parser flags. */
  clean_flags(internal_parser->flags);

  u_int len = header->len;
  if (len < sizeof(struct ether_header)) {
    fprintf(stderr, "incomplated packet\n");
    return;
  }

  /* Get Ethernet header. */
  internal_parser->flags.ether = true;
  struct ether_header* eth_header = (struct ether_header*)pkt_data;
  int ether_header_len = sizeof(struct ether_header);
  strncpy(internal_parser->ether->dhost, mac_ntoa(eth_header->ether_dhost), sizeof(internal_parser->ether->dhost));
  strncpy(internal_parser->ether->shost, mac_ntoa(eth_header->ether_shost), sizeof(internal_parser->ether->shost));
  internal_parser->ether->type = ntohs(eth_header->ether_type);
  /* End of Ethernet header. */

  /* Get ip header. */
  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    internal_parser->flags.ip = true;
    struct ip_parser* ip = (struct ip_parser*)(pkt_data + ether_header_len);
    int ip_header_len = IP_HL(ip) << 2;
    len -= ether_header_len;
    if (len < sizeof(struct ip_parser)) {
      fprintf(stderr, "truncated ip %d\n", len);
      return;
    }

    internal_parser->ip = ip;
    /* As struct 'ip' get network byte order, internal_ip need change to host byte order. */
    internal_parser->ip->ip_len = ntohs(ip->ip_len);
    internal_parser->ip->ip_id = ntohs(ip->ip_id);
    internal_parser->ip->ip_off = ntohs(ip->ip_off);
    internal_parser->ip->ip_sum = ntohs(ip->ip_sum);
    /* End of IP header. */

    /* Get tcp header. */
    if (u_char(ip->ip_p) == IPPROTO_TCP) {
      internal_parser->flags.tcp = true;
      struct tcphdr* tcp_header = (struct tcphdr*)(pkt_data + ether_header_len + ip_header_len);
      int tcp_header_len = tcp_header->th_off << 2;
      len -= ip_header_len;

      struct tcp_parser* tcp = internal_parser->tcp;
      tcp->sport = ntohs(tcp_header->th_sport);
      tcp->dport = ntohs(tcp_header->th_dport);
      tcp->seq = ntohl(tcp_header->th_seq);
      tcp->ack = ntohl(tcp_header->th_ack);
      tcp->header_len = tcp_header->th_off << 2;
      tcp->flags = tcp_header->th_flags;
      tcp->windows = ntohs(tcp_header->window);
      tcp->checksum = ntohs(tcp_header->th_sum);
      tcp->urp = ntohs(tcp_header->th_urp);
      /* End of tcp header. */

      /* Get http header. */
      if (tcp->sport == 80 || tcp->dport == 80) {
        internal_parser->flags.http = true;
        const u_char* http_data = pkt_data + ether_header_len + ip_header_len + tcp_header_len;
        len -= tcp_header_len;

        struct http_parser* hp = internal_parser->http;
        http_parse(http_handle, http_data, len, hp);
      }
      /* End of http header. */

    }
    /* Get udp header. */
    else if (u_char(ip->ip_p) == IPPROTO_UDP) {
      internal_parser->flags.udp = true;
      struct udphdr* udp_header = (struct udphdr*)(pkt_data + ether_header_len + ip_header_len);


      struct udp_parser* udp = internal_parser->udp;
      udp->sport = ntohs(udp_header->uh_sport);
      udp->dport = ntohs(udp_header->uh_dport);
      udp->len = ntohs(udp_header->len);
      udp->checksum = ntohs(udp_header->check);
      /* End of udp header. */
    }

  }
  /* Get back parser. */
  parser = (u_char*)internal_parser;
  /* Function show will print pkt info by layers. */
  show(internal_parser);
}

}