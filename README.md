# PParser

PParser is a fast protocol parser used to parse `HTTP` in C++ & C.

PParser uses `libpcap` as low-level packet parser, and parses `http` in `llhttp`.

## Getting started
PParser gives two types of accepting packets. One is `ONLINE_TYPE`, which you need to provide your network device, PParser will parse packets from your device. Another is `OFFLINE_TYPE`, in which you need to give a pcap file, PParser will parse packets in the file.

PParser can easily be used. Just include the file `lpcap.h`, init a `pcap_t*` handle, `pkt_parser*` parser in your program. And choose one type. A demo shows how to use.

``` C++
#include "src/lpcap.h"

using namespace sunfor3;

int main() {
    pcap_t* handle;
    /* ONLINE_TYPE */
    std::string interface = "device"; // device name
    handle = init_pcap(ONLINE_TYPE, interface.c_str());

    /* OFFLINE_TYPE */
    std::string location = "location"; // pcap location
    handle = init_pcap(OFFLINE_TYPE, location.c_str());
    struct pkt_parser* parser;

    parser = init_parser();

    packet_process(handle, parser);

    end_pcap(handle);
    end_parser(parser);
    return 0;
}
```

Output will be like:

```
###[ Ethernet ]###
   dst= 00:15:5d:76:11:d2 
   src= 00:15:5d:76:1c:42 
   type= 0x800 
###[ IP ]###
   version= 4 
   ihl= 20 
   tos= 0x00 
   len= 117 
   id= 0xaa9e 
   flags= -D- 
   off= 0x00 
   ttl= 64 
   proto= 6 
   chksum= 0xee93 
   src= 172.25.53.57 
   dst= 14.215.177.39 
###[ TCP ]###
   sport= 60360 
   dport= 80 
   seq= 1099063757 
   ack= 254112396 
   header len= 20 
   flags= ---AP--- 
   windows= 502 
   checksum= 0xc628 
   urp= 0 
###[ HTTP ]###
 ###[ HTTPR EQUEST ]###
   method= GET 
   url= / 
   version= 1.1 
   Accept= */* 
   User-Agent= curl/7.68.0 
   Host= www.baidu.com 
```

## Installation
PParser depends on two libraries: [llhttp](https://github.com/nodejs/llhttp) and [libpcap](https://www.tcpdump.org/). Make sure your machine has installed these two libraries. `llhttp` won't install its library in `usr/local/lib`, it's recommended to move `.a` by yourself or add a search path in `CMake`.