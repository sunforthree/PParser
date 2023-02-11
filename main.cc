#include "src/lpcap.h"

using namespace sunfor3;

int main() {
    pcap_t* handle;
    std::string interface = "ens33";
    std::string location = "/home/sun/traffic/dns_http_3packages.pcapng";
    struct pkt_parser* parser;

    // handle = init_pcap(ONLINE_TYPE, interface.c_str());
    handle = init_pcap(OFFLINE_TYPE, location.c_str());
    parser = init_parser();

    packet_process(handle, parser);

    end_pcap(handle);
    end_parser(parser);
    return 0;
}