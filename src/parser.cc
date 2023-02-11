#include "parser.h"

namespace sunfor3 {
struct pkt_parser* init_parser() {
  struct pkt_parser* parser;
  
  parser = new struct pkt_parser;
  parser->ether = new struct ether_parser;
  // parser->ip = new struct ip_parser;
  parser->tcp = new struct tcp_parser;
  parser->http = new struct http_parser;
  parser->http->request = new struct http_request;
  parser->http->response = new struct http_response;

  return parser;
}

// Delete memory which maybe malloc.
// (Ehter and IP use the raw ptr of packet.)
void end_parser(struct pkt_parser* parser) {
  if (parser->ether != nullptr)
    delete parser->ether;
  // if (parser->ip != nullptr)
  //   delete parser->ip;
  if (parser != nullptr && parser->tcp != nullptr)
    delete parser->tcp;
  if (parser != nullptr && parser->http != nullptr) {
    if (parser->http->request != nullptr)
      delete parser->http->request;
    if (parser->http->response != nullptr)
      delete parser->http->response;
    delete parser->http;
  }
  if (parser != nullptr)
    delete parser;
}

void show(struct pkt_parser* parser) {
  if (parser->flags.ether && parser->ether != nullptr) {
    printf("###[ Ethernet ]###\n");
    printf("   dst= %s \n", parser->ether->dhost);
    printf("   src= %s \n", parser->ether->shost);
    printf("   type= 0x%02x \n", parser->ether->type);
  }
  if (parser->flags.ip && parser->ip != nullptr) {
    printf("###[ IP ]###\n");
    printf("   version= %d \n", IP_V(parser->ip));
    printf("   ihl= %d \n", IP_HL(parser->ip) << 2);
    printf("   tos= 0x%02x \n", parser->ip->ip_tos);
    printf("   len= %d \n", parser->ip->ip_len);
    printf("   id= 0x%02x \n", parser->ip->ip_id);
    printf("   flags= %s \n", ip_ftoa(parser->ip->ip_off));
    printf("   off= 0x%02x \n", parser->ip->ip_off & IP_OFFMASK);
    printf("   ttl= %d \n", parser->ip->ip_ttl);
    printf("   proto= %d \n", parser->ip->ip_p);
    printf("   chksum= 0x%02x \n", parser->ip->ip_sum);
    printf("   src= %s \n", ip_ntoa(&(parser->ip->ip_src)));
    printf("   dst= %s \n", ip_ntoa(&(parser->ip->ip_dst)));
  }
  if (parser->flags.tcp && parser->tcp != nullptr) {
    printf("###[ TCP ]###\n");
    printf("   sport= %d \n", parser->tcp->sport);
    printf("   dport= %d \n", parser->tcp->dport);
    printf("   seq= %d \n", parser->tcp->seq);
    printf("   ack= %d \n", parser->tcp->ack);
    printf("   header len= %d \n", parser->tcp->header_len);
    printf("   flags= %s \n", tcp_ftoa(parser->tcp->flags));
    printf("   windows= %d \n", parser->tcp->windows);
    printf("   checksum= 0x%02x \n", parser->tcp->checksum);
    printf("   urp= %d \n", parser->tcp->urp);
  }
  if (parser->flags.http && parser->http != nullptr) {
    struct http_parser* hp = parser->http;
    printf("###[ HTTP ]###\n");
    /* HTTP_REQUEST */
    if (hp->type == 1) {
      printf(" ###[ HTTPR EQUEST ]###\n");
      printf("   method= %s \n", hp->request->method);
      printf("   url= %s \n", hp->request->url.c_str());
      printf("   version= %s \n", hp->request->version.c_str());
    }
    /* HTTP_RESPONSE */
    else if (hp->type == 2) {
      printf(" ###[ HTTP RESPONSE ]###\n");
      printf("   version= %s \n", hp->response->version.c_str());
      printf("   status= %d %s \n", hp->response->status_code, hp->response->status_name.c_str());
    }
    for(auto&& [field, value] : hp->header) {
      std::cout << "   " << field << "= " << value << " \n";
    }
  }
  printf("\n");
}

char* mac_ntoa(u_char *d) {
  static char str[MAC_ADDRSTRLEN];

  snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

  return str;
}

char* ip_ftoa(uint16_t flag) {
  /* Pre define flags. */
  static int f[] = { 'R', 'D', 'M' };
#define IP_FLG_MAX (sizeof(f) / sizeof(f[0]))
  /* Pre define buffer. */
  static char str[IP_FLG_MAX + 1];
  uint16_t mask = 1 << 15;

  int i;
  for (i = 0; i < IP_FLG_MAX; ++i) {
    if (mask & flag)
      str[i] = f[i];
    else
      str[i] = '-';
    mask >>= 1;
  }
  str[i] = '\0';

  return str;
}

char* ip_ntoa(void* address) {
  static char str[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, address, str, sizeof(str));

  return str;
}

char* tcp_ftoa(uint8_t flag) {
  /* Pre define flags. */
  static int f[] = {'W', 'E', 'U', 'A', 'P', 'R', 'S', 'F'};
#define TCP_FLG_MAX (sizeof(f) / sizeof(f[0]))
  /* Pre define buffer. */
  static char str[TCP_FLG_MAX + 1];
  uint32_t mask = 1 << 7;

  int i;
  for (i = 0; i < TCP_FLG_MAX; ++i) {
    if (mask & flag)
      str[i] = f[i];
    else
      str[i] = '-';
    mask >>= 1;
  }
  str[i] = '\0';

  return str;
}

void clean_flags(struct proto_flag &flags) {
  flags.ether = false;
  flags.ip = false;
  flags.tcp = false;
  flags.udp = false;
  flags.http = false;
}

}