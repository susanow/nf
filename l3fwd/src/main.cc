
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <vector>
#include <dpdk/dpdk.h>
#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>
#include <slankdev/exception.h>
#include <slankdev/socketfd.h>
#include <slankdev/net/addr.h>

#define DO_RFC_1812_CHECKS
#define RTE_LOGTYPE_L3FWD RTE_LOGTYPE_USER1
#define MAX_PKT_BURST     32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MAX_RX_QUEUE_PER_LCORE 16
#define	MAX_TX_BURST	  (MAX_PKT_BURST / 2)
#define PREFETCH_OFFSET	  3
#define	BAD_PORT ((uint16_t)-1)
#define FWDSTEP	4
#define	MASK_ETH 0x3f

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_rx_queue {
	uint8_t port_id;
	uint8_t queue_id;
} __rte_cache_aligned;

struct lcore_conf {
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t n_tx_port;
	uint16_t tx_port_id[RTE_MAX_ETHPORTS];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
	void *ipv4_lookup_struct;
	void *ipv6_lookup_struct;
} __rte_cache_aligned;

/* Send burst of packets on an output interface */
static inline int
send_burst(struct lcore_conf *qconf, uint16_t n, uint8_t port)
{
	struct rte_mbuf **m_table;
	int ret;
	uint16_t queueid;

	queueid = qconf->tx_queue_id[port];
	m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

	ret = rte_eth_tx_burst(port, queueid, m_table, n);
	if (unlikely(ret < n)) {
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}

	return 0;
}

/* Enqueue a single packet, and send burst if queue is filled */
static inline int
send_single_packet(struct lcore_conf *qconf,
		struct rte_mbuf *m, uint8_t port)
{
	uint16_t len;

	len = qconf->tx_mbufs[port].len;
	qconf->tx_mbufs[port].m_table[len] = m;
	len++;

	/* enough pkts to be sent */
	if (unlikely(len == MAX_PKT_BURST)) {
		send_burst(qconf, MAX_PKT_BURST, port);
		len = 0;
	}

	qconf->tx_mbufs[port].len = len;
	return 0;
}

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

/* Configurable number of RX/TX ring descriptors */
#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

volatile bool force_quit;
uint64_t dest_eth_addr[RTE_MAX_ETHPORTS];
struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
xmm_t val_eth[RTE_MAX_ETHPORTS];
struct lcore_conf lcore_conf[RTE_MAX_LCORE];

struct lcore_params {
	uint8_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
} __rte_cache_aligned;
static struct lcore_params lcore_params_array_default[] = {
	{0, 0, 1},
	{1, 0, 2},
};
static struct lcore_params* lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params =
  sizeof(lcore_params_array_default)/sizeof(lcore_params_array_default[0]);
static struct rte_eth_conf port_conf;
std::vector<struct rte_mempool*> pktmbuf_pool;
std::vector<struct rte_lpm*> ipv4_l3fwd_lpm_lookup_struct;

struct l3fwd_lkp_mode {
	void  (*setup)(int);
	int   (*main_loop)(void *);
	void* (*get_ipv4_lookup_struct)(int);
};
static struct l3fwd_lkp_mode l3fwd_lkp;

#define IPV4_L3FWD_LPM_NUM_ROUTES \
	(sizeof(ipv4_l3fwd_lpm_route_array) \
   / sizeof(ipv4_l3fwd_lpm_route_array[0]))
#define IPV4_L3FWD_LPM_MAX_RULES    1024
#define IPV4_L3FWD_LPM_NUMBER_TBL8S (1 << 8)

// extern std::vector<struct rte_lpm*> ipv4_l3fwd_lpm_lookup_struct;

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

static inline __attribute__((always_inline)) void
l3fwd_lpm_simple_forward(rte_mbuf *m, uint8_t portid,
		struct lcore_conf *qconf)
{
	ether_hdr* eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

	if (RTE_ETH_IS_IPV4_HDR(m->packet_type)) {
		/* Handle IPv4 headers.*/
    struct ipv4_hdr* ipv4_hdr = (struct ipv4_hdr*)(eth_hdr + 1);
    uint8_t dst_port = lpm_get_ipv4_dst_port(
        ipv4_hdr, portid, qconf->ipv4_lookup_struct);
    printf("%s -> dstport:%u \n",
        slankdev::inaddr2str(ipv4_hdr->dst_addr).c_str(), dst_port);
		if (dst_port >= RTE_MAX_ETHPORTS || (1 << dst_port) == 0) dst_port = portid;

		*(uint64_t *)&eth_hdr->d_addr = dest_eth_addr[dst_port]; /* dst addr */
		ether_addr_copy(&ports_eth_addr[dst_port], &eth_hdr->s_addr); /* src addr */
		send_single_packet(qconf, m, dst_port);

	} else {
		rte_pktmbuf_free(m);
	}
}


int lpm_main_loop(void*)
{
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
		US_PER_S * BURST_TX_DRAIN_US;

	uint64_t prev_tsc, diff_tsc, cur_tsc;
	prev_tsc = 0;

	const unsigned lcore_id = rte_lcore_id();
	struct lcore_conf* qconf = &lcore_conf[lcore_id];
	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n", lcore_id);

	for (size_t i = 0; i < qconf->n_rx_queue; i++) {
		uint8_t portid = qconf->rx_queue_list[i].port_id;
		uint8_t queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, L3FWD,
			" -- lcoreid=%u portid=%hhu rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	while (!force_quit) {

		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (size_t i = 0; i < qconf->n_tx_port; ++i) {
				uint8_t portid = qconf->tx_port_id[i];
				if (qconf->tx_mbufs[portid].len == 0)
					continue;
				send_burst(qconf,
					qconf->tx_mbufs[portid].len,
					portid);
				qconf->tx_mbufs[portid].len = 0;
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (size_t i = 0; i < qconf->n_rx_queue; ++i) {
      struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
			uint8_t portid = qconf->rx_queue_list[i].port_id;
			uint8_t queueid = qconf->rx_queue_list[i].queue_id;

      size_t nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst, MAX_PKT_BURST);
			if (nb_rx == 0) continue;
      for (size_t j=0; j<nb_rx; j++)
        l3fwd_lpm_simple_forward(pkts_burst[j], portid, qconf);
		}
	}
  return 0;
}


void setup_lpm(const int socketid)
{
	struct rte_lpm_config config_ipv4;
	unsigned i;
	int ret;
	char s[64];

	/* create the LPM table */
	config_ipv4.max_rules = IPV4_L3FWD_LPM_MAX_RULES;
	config_ipv4.number_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S;
	config_ipv4.flags = 0;
	snprintf(s, sizeof(s), "IPV4_L3FWD_LPM_%d", socketid);
	ipv4_l3fwd_lpm_lookup_struct[socketid] =
			rte_lpm_create(s, socketid, &config_ipv4);
	if (ipv4_l3fwd_lpm_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the l3fwd LPM table on socket %d\n",
			socketid);

	/* populate the LPM table */
	for (i = 0; i < IPV4_L3FWD_LPM_NUM_ROUTES; i++) {

		/* skip unused ports */
		if ((1 << ipv4_l3fwd_lpm_route_array[i].if_out) == 0)
			continue;

		ret = rte_lpm_add(
      ipv4_l3fwd_lpm_lookup_struct[socketid],
			ipv4_l3fwd_lpm_route_array[i].ip,
			ipv4_l3fwd_lpm_route_array[i].depth,
			ipv4_l3fwd_lpm_route_array[i].if_out);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Unable to add entry %u to the l3fwd LPM table on socket %d\n",
				i, socketid);
		}

		printf("LPM: Adding route 0x%08x / %d (%d)\n",
			(unsigned)ipv4_l3fwd_lpm_route_array[i].ip,
			ipv4_l3fwd_lpm_route_array[i].depth,
			ipv4_l3fwd_lpm_route_array[i].if_out);
	}
}


void* lpm_get_ipv4_l3fwd_lookup_struct(const int socketid)
{
	return ipv4_l3fwd_lpm_lookup_struct[socketid];
}





static void
check_lcore_params(void)
{
	for (size_t i = 0; i < nb_lcore_params; ++i) {
		uint32_t queue = lcore_params[i].queue_id;
		if (queue >= MAX_RX_QUEUE_PER_PORT) {
      std::string e = slankdev::format("invalid queue number: %hhu\n", queue);
      throw slankdev::exception(e.c_str());
		}
		uint32_t lcore = lcore_params[i].lcore_id;
		if (!rte_lcore_is_enabled(lcore)) {
      std::string e =  slankdev::format(
          "error: lcore %hhu is not enabled in lcore mask\n", lcore);
      throw slankdev::exception(e.c_str());
		}
	}
}


static void
check_ports_config()
{
  size_t nb_ports = rte_eth_dev_count();
  if (nb_ports != 2) {
    throw slankdev::exception(
      "This application support only 2 ports mode");
  }

	for (uint16_t i = 0; i < nb_lcore_params; ++i) {
    unsigned portid = lcore_params[i].port_id;
		if (portid >= nb_ports) {
      auto s = slankdev::format(
          "port %u is not present on the board\n", portid);
      throw slankdev::exception(s.c_str());
		}
	}
}


static uint8_t
get_port_n_rx_queues(const uint8_t port)
{
	int queue = -1;
	for (size_t i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].port_id == port) {
			if (lcore_params[i].queue_id == queue+1)
				queue = lcore_params[i].queue_id;
			else
				rte_exit(EXIT_FAILURE, "queue ids of the port %d must be"
						" in sequence and must start with 0\n",
						lcore_params[i].port_id);
		}
	}
	return (uint8_t)(++queue);
}

static void
init_lcore_rx_queues(void)
{
	for (size_t i = 0; i < nb_lcore_params; ++i) {
    uint8_t lcore = lcore_params[i].lcore_id;
    uint16_t nb_rx_queue = lcore_conf[lcore].n_rx_queue;
		if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
      auto s = slankdev::format(
          "error: too many queues (%u) for lcore: %u\n",
          (unsigned)nb_rx_queue + 1, (unsigned)lcore);
      throw slankdev::exception(s.c_str());
		} else {
			lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
				lcore_params[i].port_id;
			lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
				lcore_params[i].queue_id;
			lcore_conf[lcore].n_rx_queue++;
		}
	}
}

static void
init_mem()
{
  constexpr size_t nb_mbuf = 8192;
	for (size_t lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

    int socketid = rte_lcore_to_socket_id(lcore_id);
		if (pktmbuf_pool[socketid] == nullptr) {
      std::string s = slankdev::format("mbuf_pool_%d", socketid);
			pktmbuf_pool[socketid] = dpdk::mp_alloc(s.c_str(), socketid, nb_mbuf);
      printf("Allocated mbuf pool on socket %d\n", socketid);

			l3fwd_lkp.setup(socketid);
		}
    struct lcore_conf* qconf = &lcore_conf[lcore_id];
		qconf->ipv4_lookup_struct = l3fwd_lkp.get_ipv4_lookup_struct(socketid);
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

void
init_global_struct()
{
	memset(&port_conf, 0, sizeof(port_conf));
	port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
	port_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
	port_conf.rxmode.split_hdr_size = 0;
	port_conf.rxmode.header_split   = 0; /**< Header Split disabled */
	port_conf.rxmode.hw_ip_checksum = 1; /**< IP checksum offload enabled */
	port_conf.rxmode.hw_vlan_filter = 0; /**< VLAN filtering disabled */
	port_conf.rxmode.jumbo_frame    = 0; /**< Jumbo Frame Support disabled */
	port_conf.rxmode.hw_strip_crc   = 1; /**< CRC stripped by hardware */
	port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
	port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP;
	port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;

	memset(&l3fwd_lkp, 0, sizeof(l3fwd_lkp));
	l3fwd_lkp.setup                  = setup_lpm;
	l3fwd_lkp.main_loop              = lpm_main_loop;
	l3fwd_lkp.get_ipv4_lookup_struct = lpm_get_ipv4_l3fwd_lookup_struct;

  pktmbuf_pool.resize(4);
  ipv4_l3fwd_lpm_lookup_struct.resize(4);
  for (size_t i=0; i<4; i++) {
    pktmbuf_pool[i] = nullptr;
    ipv4_l3fwd_lpm_lookup_struct[i] = nullptr;
  }
}

int main(int argc, char **argv)
{
	init_global_struct();
  dpdk::dpdk_boot(argc, argv);
	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	for (uint16_t portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		dest_eth_addr[portid] =
			ETHER_LOCAL_ADMIN_ADDR + ((uint64_t)portid << 40);
		*(uint64_t *)(val_eth + portid) = dest_eth_addr[portid];
	}

	check_lcore_params();
	init_lcore_rx_queues();
	check_ports_config();
  init_mem();

	const size_t nb_ports = rte_eth_dev_count();
	const size_t nb_lcores = rte_lcore_count();
	for (uint16_t portid=0; portid<nb_ports; portid++) {
		printf("Initializing port %d ... \n", portid );
		fflush(stdout);

    uint16_t nb_rx_queue = get_port_n_rx_queues(portid);
    uint32_t n_tx_queue  = nb_lcores;

		if (n_tx_queue > MAX_TX_QUEUE_PER_PORT)
      n_tx_queue = MAX_TX_QUEUE_PER_PORT;

    dpdk::port_configure(portid, nb_rx_queue,
        (uint16_t)n_tx_queue, &port_conf,
        pktmbuf_pool[rte_eth_dev_socket_id(portid)]);

		rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
    auto s = slankdev::macaddr2str((uint8_t*)(&ports_eth_addr[portid]));
    printf(" Address: %s, ", s.c_str());
		printf("Destination: %s, \n", slankdev::macaddr2str(
          (uint8_t*)&dest_eth_addr[portid]).c_str());

		/* prepare src MACs for each port.  */
		ether_addr_copy(&ports_eth_addr[portid],
			(struct ether_addr *)(val_eth + portid) + 1);

		/* init one TX queue per couple (lcore,port) */
		for (uint16_t queueid=0,lcore_id=0; lcore_id<RTE_MAX_LCORE; lcore_id++) {
			if (rte_lcore_is_enabled(lcore_id) == 0) continue;
      struct lcore_conf* qconf = &lcore_conf[lcore_id];
			qconf->tx_queue_id[portid] = queueid;
			queueid++;
			qconf->tx_port_id[qconf->n_tx_port] = portid;
			qconf->n_tx_port++;
		}
    rte_eth_promiscuous_enable(portid);
	}

	rte_eal_mp_remote_launch(l3fwd_lkp.main_loop, NULL, CALL_MASTER);
  rte_eal_mp_wait_lcore();
	for (uint16_t portid = 0; portid < nb_ports; portid++) {
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
	}
	return 0;
}


