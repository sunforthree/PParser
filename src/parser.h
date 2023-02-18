#ifndef _SRC_PARSER_H_
#define _SRC_PARSER_H_

#include <iostream>
#include <unordered_map>
#include <string>
#include <vector>

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

// C++ infterface to parse raw data.
// Defined sorts of struct parsers save protocol data.
// --------------------------------------------------

namespace sunfor3 {

#define MAC_ADDRSTRLEN 2*6+5+1

struct proto_flag {
  bool ether = false;
  bool ip = false;
  bool tcp = false;
  bool udp = false;
  bool http = false;
};

struct ether_parser {
  char dhost[MAC_ADDRSTRLEN]; /* destination eth addr	*/
  char shost[MAC_ADDRSTRLEN]; /* source ether addr	*/
  uint16_t type;              /* packet type ID field	*/
};

struct ip_parser {
  uint8_t ip_vhl;     /* header length, version */
#define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)
  uint8_t ip_tos;    /* type of service */
  uint16_t ip_len;   /* total length */
  uint16_t ip_id;    /* identification */
  uint16_t ip_off;   /* fragment offset field */
#define	IP_RF 0x8000  /* reserved fragment flag */
#define	IP_DF 0x4000  /* dont fragment flag */
#define	IP_MF 0x2000  /* more fragments flag */
#define	IP_OFFMASK 0x1fff /* mask for fragmenting bits */
  uint8_t ip_ttl;     /* time to live */
  uint8_t ip_p;       /* protocol */
  uint16_t ip_sum;    /* checksum */
  struct in_addr ip_src, ip_dst;  /* source and dest address */
};

struct tcp_parser {
  // https://en.wikipedia.org/wiki/Transmission_Control_Protocol
  uint16_t sport;
  uint16_t dport;
  uint32_t seq;
  uint32_t ack;
  uint8_t header_len;
  uint8_t flags;
  uint16_t windows;
  uint16_t checksum;
  uint16_t urp;   /* urgent pointer */
};

struct udp_parser {
  uint16_t sport;
  uint16_t dport;
  uint16_t len;
  uint16_t checksum;
};

struct http_parser {
  uint8_t type;
  struct http_request* request;
  struct http_response* response;
  std::unordered_map<std::string, std::string> header;
};

struct http_request {
  const char* method;
  std::string url;
  std::string version;
};
struct http_response {
  std::string version;
  uint16_t status_code;
  std::string status_name;
};

struct pkt_parser {
  struct proto_flag flags;
  struct ether_parser* ether;
  struct ip_parser* ip;
  struct tcp_parser* tcp;
  struct udp_parser* udp;
  struct http_parser* http;
};

struct pkt_parser* init_parser();

void end_parser(struct pkt_parser* parser);

// Print every layers in parser.
// From l2 - L5.
void show(struct pkt_parser* parser);

// Convert mac to canonical format.
// e.g.: 00:00:00:00:00:00
char* mac_ntoa(u_char *d);

// Convert ip flag to str.
char* ip_ftoa(uint16_t flag);

// Convert ip address to str.
char* ip_ntoa(void* address);

// Convert tcp flag to str.
char* tcp_ftoa(uint8_t flag);

// Clean proto_flag.
void clean_flags(struct proto_flag &flags);

} /* namespace sunfor3 */

#endif  // _SRC_PARSER_H_