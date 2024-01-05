#include <lpcap.h>
#include <chrono>

using namespace sunfor3;

int main() {
  std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
  pcap_t* handle = nullptr;
  std::string interface = "ens33";
  std::string location = "/home/sun/traffic/out.pcapng";
  struct pkt_parser* parser;
  for (int i = 0; i < 100; ++i) {
    // handle = init_pcap(ONLINE_TYPE, interface.c_str());
    handle = init_pcap(OFFLINE_TYPE, location.c_str());
    parser = init_parser();

    packet_process(handle, parser);

    end_pcap(handle);
    end_parser(parser);
  }
  std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
  std::cout << "Time difference = " << std::chrono::duration_cast<std::chrono::seconds>(end - begin).count() << "[s]" << std::endl;
  std::cout << "Time difference = " << std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count() << "[µs]" << std::endl;
  std::cout << "Time difference = " << std::chrono::duration_cast<std::chrono::nanoseconds> (end - begin).count() << "[ns]" << std::endl;
  return 0;
}