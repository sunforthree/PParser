#ifndef _SRC_LPCAP_H_
#define _SRC_LPCAP_H_

#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>

#include "http.h"

// C++ interface to the libpcap.
// It gives sorts of functions to get & parser packets.
// ----------------------------------------------------

namespace sunfor3 {

extern llhttp_cube_t* http_handle;

enum PcapType {
    OFFLINE_TYPE = 0,
    ONLINE_TYPE,
};

// pkt_info is a struct that contains 
// the length of the packet and the packet data.
struct pkt_info {
  bpf_u_int32 length;
  u_char* pkt_data;
};

// Init a handle, the word `type` determines whether
// word `location` is a file or a device.
// OFFLINE_TYPE -> file
// ONLINE_TYPE  -> deivce  
pcap_t* init_pcap(PcapType type, const char* location);

// If handle not nullptr, close it.
void end_pcap(pcap_t* handle);

// Default packet handler.
// 
void packet_handler(u_char* user_Data, const struct pcap_pkthdr* header, const u_char* pkt_data);

// Main function, process packet here,
// pass a function ptr to it do the real handle things.
// 'pcap_handler' parameter is as follows: 
// (u_char *, const struct pcap_pkthdr *, const u_char *)
void packet_process(pcap_t* handle, struct pkt_parser* parser, pcap_handler handler=packet_handler);

// Main function, process packet here,
// pass a function ptr to it do the real handle things.
// 'pcap_handler' parameter is as follows: 
// (u_char *, const struct pcap_pkthdr *, const u_char *)
// The defference between last one is:
// this pass a std::unordered_map to it.
// Make sure when using this, pass yourself handler to it.
void packet_process(pcap_t* handle, map_parser* parser, pcap_handler handler=packet_handler);

} /* namespace sunfor3 */

#endif  // _SRC_LPCAP_H_