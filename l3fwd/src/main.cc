
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include <vector>
#include <dpdk/dpdk.h>
#include <slankdev/exception.h>
#include <slankdev/socketfd.h>
#include <slankdev/net/addr.h>

#define RTE_LOGTYPE_L3FWD RTE_LOGTYPE_USER1
#define MAX_RX_QUEUE_PER_LCORE 16

struct ipv4_l3fwd_lpm_route {
	uint32_t ip;
	uint8_t  depth;
	uint8_t  if_out;
};
static struct ipv4_l3fwd_lpm_route
      ipv4_l3fwd_lpm_route_array[] = {
    // {IPv4(192, 168, 0, 0), 24, 1},
    {IPv4(1, 0, 0, 0), 24, 0},
    {IPv4(1, 1, 0, 0), 24, 1},
    {IPv4(1, 2, 0, 0), 24, 0},
    {IPv4(1, 3, 0, 0), 24, 1},
    {IPv4(1, 4, 0, 0), 24, 0},
    {IPv4(1, 5, 0, 0), 24, 1},
    {IPv4(1, 6, 0, 0), 24, 0},
    {IPv4(1, 7, 0, 0), 24, 1},
    {IPv4(1, 8, 0, 0), 24, 0},
    {IPv4(1, 9, 0, 0), 24, 1},
};


struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
std::vector<struct rte_mempool*> pktmbuf_pool;
std::vector<struct rte_lpm*> lpm_lookup_struct;


static inline uint8_t
lpm_get_ipv4_dst_port(void *ipv4_hdr,
    uint8_t portid, void *lookup_struct)
{
	uint32_t next_hop;
	struct rte_lpm *ipv4_l3fwd_lookup_struct =
		(struct rte_lpm *)lookup_struct;

	return (uint8_t) ((rte_lpm_lookup(ipv4_l3fwd_lookup_struct,
		rte_be_to_cpu_32(((struct ipv4_hdr *)ipv4_hdr)->dst_addr),
		&next_hop) == 0) ? next_hop : portid);
}


int lpm_main_loop(void*)
{
  const size_t n_port = rte_eth_dev_count();
	while (true) {

    for (size_t pid=0; pid<n_port; pid++) {

      constexpr size_t MAX_PKT_BURST = 32;
      struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
			uint8_t portid = pid;
			uint8_t queueid = 0;
      auto ipv4_lookup_struct = lpm_lookup_struct[rte_socket_id()];

      size_t n_recv = rte_eth_rx_burst(portid, queueid, pkts_burst, MAX_PKT_BURST);
			if (n_recv == 0) continue;
      for (size_t j=0; j<n_recv; j++) {

        rte_mbuf* m = pkts_burst[j];
        ether_hdr* eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
        if (!RTE_ETH_IS_IPV4_HDR(m->packet_type)) rte_pktmbuf_free(m);

        /* Handle IPv4 headers.*/
        struct ipv4_hdr* ipv4_hdr = (struct ipv4_hdr*)(eth_hdr + 1);
        uint8_t dst_port = lpm_get_ipv4_dst_port(
            ipv4_hdr, portid, ipv4_lookup_struct);
        printf("%s -> dstport:%u \n",
            slankdev::inaddr2str(ipv4_hdr->dst_addr).c_str(), dst_port);
        if (dst_port >= RTE_MAX_ETHPORTS || (1 << dst_port) == 0)
          dst_port = portid;

        /* Craft Ethernet Header */
        *(uint64_t*)&eth_hdr->d_addr = 0xffffffffffff;
        ether_addr_copy(&ports_eth_addr[dst_port], &eth_hdr->s_addr);

        size_t ret = rte_eth_tx_burst(dst_port, queueid, &m, 1);
        if (ret < 1) rte_pktmbuf_free(m);

      } /* for (size_t j=0; j<n_recv; j++) */
		} /* for (size_t pid=0; pid<n_port; pid++) */
	} /* while (true) */
  return 0;
}

void setup_lpm(const int socketid)
{
	char s[64];
	snprintf(s, sizeof(s), "IPV4_L3FWD_LPM_%d", socketid);

	/* create the LPM table */
	struct rte_lpm_config config_ipv4;
  constexpr size_t IPV4_L3FWD_LPM_MAX_RULES    = 1024;
  constexpr size_t IPV4_L3FWD_LPM_NUMBER_TBL8S = (1<<8);
	config_ipv4.max_rules = IPV4_L3FWD_LPM_MAX_RULES;
	config_ipv4.number_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S;
	config_ipv4.flags = 0;
	lpm_lookup_struct[socketid] =
			rte_lpm_create(s, socketid, &config_ipv4);
	if (lpm_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the l3fwd LPM table on socket %d\n",
			socketid);

	/* populate the LPM table */
  const size_t n_routes = sizeof(ipv4_l3fwd_lpm_route_array)
       / sizeof(ipv4_l3fwd_lpm_route_array[0]);
	for (size_t i = 0; i <n_routes ; i++) {

		/* skip unused ports */
		if ((1 << ipv4_l3fwd_lpm_route_array[i].if_out) == 0)
			continue;

    int ret = rte_lpm_add(
      lpm_lookup_struct[socketid],
			ipv4_l3fwd_lpm_route_array[i].ip,
			ipv4_l3fwd_lpm_route_array[i].depth,
			ipv4_l3fwd_lpm_route_array[i].if_out);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Unable to add entry %zd to the l3fwd LPM table on socket %d\n",
				i, socketid);
		}

		printf("LPM: Adding route 0x%08x / %d (%d)\n",
			(unsigned)ipv4_l3fwd_lpm_route_array[i].ip,
			ipv4_l3fwd_lpm_route_array[i].depth,
			ipv4_l3fwd_lpm_route_array[i].if_out);
	}
}

int main(int argc, char **argv)
{
  dpdk::dpdk_boot(argc, argv);

  static struct rte_eth_conf port_conf;
	memset(&port_conf, 0, sizeof(port_conf));
  dpdk::init_portconf(&port_conf);
	port_conf.rxmode.hw_ip_checksum = 1; /**< IP checksum offload enabled */
	port_conf.rxmode.hw_strip_crc   = 1; /**< CRC stripped by hardware */

  pktmbuf_pool.resize(2);
  pktmbuf_pool[0] = dpdk::mp_alloc("mp0", 0, 8192);
  pktmbuf_pool[1] = dpdk::mp_alloc("mp1", 1, 8192);
  lpm_lookup_struct.resize(2);
  setup_lpm(0);
  setup_lpm(1);

	const size_t nb_ports = rte_eth_dev_count();
  if (nb_ports != 2) throw slankdev::exception("port is 2 gaii");

	for (uint16_t portid=0; portid<nb_ports; portid++) {
    dpdk::port_configure(portid, 1, 2, &port_conf,
        pktmbuf_pool[rte_eth_dev_socket_id(portid)]);
		rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
    rte_eth_promiscuous_enable(portid);
	}

  dpdk::rte_eal_remote_launch(lpm_main_loop, NULL, 1);
  rte_eal_mp_wait_lcore();
	return 0;
}


