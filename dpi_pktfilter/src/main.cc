
#include <stdio.h>
#include <stdlib.h>
#include <ndpi_main.h>
#include <slankdev/exception.h>
#include <slankdev/extra/pcap.h>
#include <slankdev/hexdump.h>
#include <slankdev/net/hdr.h>

NDPI_PROTOCOL_BITMASK all;
struct ndpi_detection_module_struct* ndpi_struct = nullptr;

#if 0
static void *get_id(const u_int8_t * ip)
{
    u_int32_t i;
    for (i = 0; i < osdpi_id_count; i++) {
        if (memcmp(osdpi_ids[i].ip, ip, sizeof(u_int8_t) * 4) == 0) {
            return osdpi_ids[i].ndpi_id;
        }
    }
    if (osdpi_id_count == MAX_OSDPI_IDS) {
        printf("ERROR: maximum unique id count (%u) has been exceeded\n", MAX_OSDPI_IDS);
        exit(-1);
    }
    else {
        struct ndpi_id_struct *ndpi_id;
        memcpy(osdpi_ids[osdpi_id_count].ip, ip, sizeof(u_int8_t) * 4);
        ndpi_id = osdpi_ids[osdpi_id_count].ndpi_id;

        osdpi_id_count += 1;
        return ndpi_id;
    }
}
#endif

static void
pcap_callback(u_char * args, const struct pcap_pkthdr *phdr, const uint8_t* packet)
{
  using namespace slankdev;
  const uint8_t* pkt_ptr = packet;

  const ether* eh = (const ether*)pkt_ptr;
  pkt_ptr += sizeof(ether);
  if (ntohs(eh->type) != 0x0800) {
    printf("not ipv4\n");
    return ;
  }

  const slankdev::ip* ih = (const slankdev::ip*)pkt_ptr;
  pkt_ptr += sizeof(slankdev::ip);
  size_t il = phdr->caplen - (pkt_ptr - packet);
  struct ndpi_id_struct* src = nullptr; // get_id((u_int8_t *)&ih->src);
  struct ndpi_id_struct* dst = nullptr; // get_id((u_int8_t *)&ih->dst);

  const uint32_t size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();
  struct ndpi_flow_struct *ipq_flow = NULL;
  ipq_flow = (struct ndpi_flow_struct*)calloc(1, size_flow_struct);

  uint64_t time  = 0;
  ndpi_protocol protocol = ndpi_detection_process_packet(
      ndpi_struct,
      ipq_flow,
      (uint8_t *)ih,
      il,
      time,
      src, dst
  );
  printf("master_protocl/protocl : %u/%u \n",
      protocol.master_protocol, protocol.protocol);
  // printf("Packet len=%d\n", phdr->caplen);
  // slankdev::hexdump(stdout, packet, phdr->caplen);
}


int main(int argc, char** argv)
{
  ndpi_struct =  ndpi_init_detection_module(0, malloc, free, (ndpi_debug_function_ptr)nullptr);

  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);

  int ret = ndpi_load_protocols_file(ndpi_struct, (char*)"proto.txt");
  if (ret < 0) {
    throw slankdev::exception("ndpi_load_protocols_file");
  }

  slankdev::pcap pcap;
  pcap.open_offline("http_flow.pcap");
  pcap.loop(0, pcap_callback, nullptr);

  ndpi_exit_detection_module(ndpi_struct, free);
  return 0;
}


