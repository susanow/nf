
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>

#include <vector>
#include <string>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>

#include <slankdev/color.h>
#include <slankdev/exception.h>
#include <slankdev/endian.h>
#include <slankdev/extra/pcap.h>

#include <ndpi_main.h>
#include <ndpi_api.h>
#include "ndpi_protocol_id2str.h"
#include "osdpi.h"


/* detection */
static struct ndpi_detection_module_struct *ndpi_struct = NULL;
static const u_int32_t detection_tick_resolution = 1000;

/* results */
static u_int64_t raw_packet_count = 0;
static u_int64_t ip_packet_count = 0;
static u_int64_t total_bytes = 0;
static u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
static u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];

std::vector<struct osdpi_id> osdpi_ids;
std::vector<struct osdpi_flow> osdpi_flows;


static void debug_printf(u_int32_t protocol, void *id_struct,
    ndpi_log_level_t log_level, const char *format, ...) {}

static struct osdpi_flow *get_osdpi_flow(const struct iphdr *iph, u_int16_t ipsize)
{
  if (ipsize < 20) return NULL;
  if ((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
      || (iph->frag_off & htons(0x1FFF)) != 0) {
    return NULL;
  }

  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int16_t ip_payload_len = ntohs(iph->tot_len) - (iph->ihl * 4);

  if (iph->saddr < iph->daddr) {
    lower_ip = iph->saddr;
    upper_ip = iph->daddr;
  } else {
    lower_ip = iph->daddr;
    upper_ip = iph->saddr;
  }

  size_t ihl = iph->ihl * 4;
  if (iph->protocol == 6 && ip_payload_len >= 20) {
    /*
     * tcp
     */
    struct tcphdr* th = (struct tcphdr*)((u_int8_t*)iph + ihl);
    if (iph->saddr < iph->daddr) {
      lower_port = th->source;
      upper_port = th->dest;
    } else {
      lower_port = th->dest;
      upper_port = th->source;
    }
  } else if (iph->protocol == 17 && ip_payload_len >= 8) {
    /*
     * udp
     */
    struct udphdr* uh = (struct udphdr*)((u_int8_t*)iph + ihl);
    if (iph->saddr < iph->daddr) {
      lower_port = uh->source;
      upper_port = uh->dest;
    } else {
      lower_port = uh->dest;
      upper_port = uh->source;
    }
  } else {
    /*
     * non tcp/udp protocols
     */
    lower_port = 0;
    upper_port = 0;
  }

  for (uint32_t i = 0; i < osdpi_flows.size(); i++) {
    if (osdpi_flows[i].protocol   == iph->protocol &&
        osdpi_flows[i].lower_ip   == lower_ip      &&
        osdpi_flows[i].upper_ip   == upper_ip      &&
        osdpi_flows[i].lower_port == lower_port    &&
        osdpi_flows[i].upper_port == upper_port) {
      return &osdpi_flows[i];
    }
  }

  printf("ADD: new flow (%02x %08x:%04x<->%08x:%04x)\n",
      iph->protocol,
      slankdev::bswap32(lower_ip  ),
      slankdev::bswap16(lower_port),
      slankdev::bswap32(upper_ip  ),
      slankdev::bswap16(upper_port));

  osdpi_flows.emplace_back();
  osdpi_flows[osdpi_flows.size()-1].protocol   = iph->protocol;
  osdpi_flows[osdpi_flows.size()-1].lower_ip   = lower_ip  ;
  osdpi_flows[osdpi_flows.size()-1].upper_ip   = upper_ip  ;
  osdpi_flows[osdpi_flows.size()-1].lower_port = lower_port;
  osdpi_flows[osdpi_flows.size()-1].upper_port = upper_port;

  osdpi_flow* f = &osdpi_flows[osdpi_flows.size()-1];
  return f;
}

static void setupDetection(void)
{
  NDPI_PROTOCOL_BITMASK all;

  /* init global detection structure */
  ndpi_struct = ndpi_init_detection_module(
      detection_tick_resolution, malloc, free, debug_printf);
  if (ndpi_struct == NULL) {
    printf("ERROR: global structure initialization failed\n");
    exit(-1);
  }

  /* enable all protocols */
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);

  /* clear memory for results */
  memset(protocol_counter, 0, (NDPI_MAX_SUPPORTED_PROTOCOLS + 1) * sizeof(u_int64_t));
  memset(protocol_counter_bytes, 0, (NDPI_MAX_SUPPORTED_PROTOCOLS + 1) * sizeof(u_int64_t));
}

static void *get_id(const u_int8_t * ip)
{
  u_int32_t i;
  for (i = 0; i < osdpi_ids.size(); i++) {
    if (memcmp(osdpi_ids[i].ip, ip, sizeof(u_int8_t) * 4) == 0) {
      return osdpi_ids[i].ndpi_id;
    }
  }

  osdpi_ids.emplace_back();
  memcpy(osdpi_ids[osdpi_ids.size()-1].ip, ip, sizeof(uint8_t)*4);
  struct ndpi_id_struct* ndpi_id = osdpi_ids[osdpi_ids.size()-1].ndpi_id;
  return ndpi_id;
}

static unsigned int
packet_processing(const uint64_t time, const struct iphdr *iph, uint16_t ipsize, uint16_t rawsize)
{
  struct ndpi_id_struct* src = (ndpi_id_struct*)get_id((u_int8_t *) & iph->saddr);
  struct ndpi_id_struct* dst = (ndpi_id_struct*)get_id((u_int8_t *) & iph->daddr);

  struct ndpi_flow_struct *ipq_flow = NULL;
  struct osdpi_flow* flow = get_osdpi_flow(iph, ipsize);
  if (flow != NULL) {
    ipq_flow = flow->ndpi_flow;
  }

  ip_packet_count++;
  total_bytes += rawsize;

  /* only handle unfragmented packets */
  ndpi_protocol protocol = {0,0};
  if ((iph->frag_off & htons(0x1FFF)) == 0) {

    /* here the actual detection is performed */
    protocol = ndpi_detection_process_packet(ndpi_struct, ipq_flow,
        (uint8_t *) iph, ipsize, time, src, dst);

  }
  else {
    static u_int8_t frag_warning_used = 0;
    if (frag_warning_used == 0) {
      printf("\n\nWARNING: fragmented ip packets are not supported and will be skipped \n\n");
      sleep(2);
      frag_warning_used = 1;
    }
    return 0;
  }

  protocol_counter[protocol.protocol]++;
  protocol_counter_bytes[protocol.protocol] += rawsize;

  if (flow != NULL) {
    flow->detected_protocol = protocol.protocol;
  }
  return 0;
}

static void printResults(void)
{
  printf("\x1b[2K\n");
  printf("pcap file contains\n");
  printf("\tip packets:   %s%-13lu%s of %lu packets total\n",
      YEL, ip_packet_count, RESET, raw_packet_count);
  printf("\tip bytes:     %s%-13lu%s\n", BLU, total_bytes     , RESET);
  printf("\tunique ids:   %s%-13zd %s\n", RED, osdpi_ids.size()  , RESET);
  printf("\tunique flows: %s%-13zd %s\n", CYN, osdpi_flows.size(), RESET);

  printf("\ndetected protocols:\n");
  for (uint32_t i = 0; i <= NDPI_MAX_SUPPORTED_PROTOCOLS; i++) {
    u_int32_t protocol_flows = 0;

    /* count flows for that protocol */
    for (uint32_t j = 0; j < osdpi_flows.size(); j++) {
      if (osdpi_flows[j].detected_protocol == i) {
        protocol_flows++;
      }
    }

    if (protocol_counter[i] > 0) {
      printf("\t%s%-20s%s"
          " packets: %s%-13lu%s"
          " bytes: %s%-13lu%s"
          " flows: %s%-13u%s\n",
          RED, ndpi_protocol_id2str(i), RESET,
          YEL, protocol_counter[i]      , RESET,
          BLU, protocol_counter_bytes[i], RESET,
          CYN, protocol_flows           , RESET );
    }
  }
  printf("\n");
}

/*
 * executed for each packet in the pcap file
 */
static void pcap_callback(u_char * args, const struct pcap_pkthdr *ph, const u_char * packet)
{
  raw_packet_count++;

  static u_int64_t lasttime = 0;
  u_int64_t time =
    ((uint64_t) ph->ts.tv_sec) * detection_tick_resolution +
    ph->ts.tv_usec / (1000000 / detection_tick_resolution);
  if (lasttime > time) {
    time = lasttime;
  }
  lasttime = time;

  const struct ethhdr *eh = (struct ethhdr *) packet;
  if (eh->h_proto == htons(ETH_P_IP) && ph->caplen >= sizeof(struct ethhdr)) {
    struct iphdr *ih = (struct iphdr *)(eh + 1);
    if (ph->caplen < ph->len) throw slankdev::exception("cap waring used");
    if (ih->version != 4)     throw slankdev::exception("ipv4 waring used");

    packet_processing(time, ih, ph->len - sizeof(struct ethhdr), ph->len);
  }
}

int main(int argc, char **argv)
{
  if (argc < 2) {
    fprintf(stderr, "Usage: %s pcapfile\n", argv[0]);
    return -1;
  }

  setupDetection();
  slankdev::pcap pcap;
  pcap.open_offline(argv[1]);
  pcap.loop(-1, &pcap_callback, NULL);
  printResults();
  return 0;
}


