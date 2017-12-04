
#include <stdio.h>
#include <string>

#include <ssn_cpu.h>
#include <ssn_common.h>
#include <ssn_port.h>
#include <ssn_log.h>
#include <ssn_thread.h>

#include <slankdev/exception.h>
#include <slankdev/string.h>
#include <slankdev/hexdump.h>

#include <stddef.h>
#include <dpdk/dpdk.h>
#include "acl_5tuple.h"


bool running = true;
void acl_filter(void* arg)
{
  acl_5tuple* acl = (acl_5tuple*)arg;

  printf("Launch %s on lcore%zd \n", __func__, ssn_lcore_id());
  while (running) {
    const size_t nb_ports = ssn_dev_count();
    for (size_t pid=0; pid<nb_ports; pid++) {
      rte_mbuf* mbufs[32];
      size_t n_recv = ssn_port_rx_burst(pid, 0, mbufs, 32);
      if (n_recv == 0) continue;

#if 0
      rte_mbuf* pass_mbufs[32];
      rte_mbuf* ejct_mbufs[32];
      size_t n_pass = acl->packet_filter_bulk(mbufs, n_recv, pass_mbufs, ejct_mbufs);
      ssn_port_tx_burst(pid^1, 0, pass_mbufs, n_pass);
      dpdk::rte_pktmbuf_free_bulk(ejct_mbufs, n_recv-n_pass);
#else
      for (size_t i=0; i<n_recv; i++) {
        /*
         * Packet Filter
         */
        static uint32_t cnt = 0;
        bool ret = acl->packet_filter_pass(mbufs[i]);
          printf("0x%04x --> %s\n", cnt++, ret?"pass":"drop");
        if (ret) {
          ssn_port_tx_burst(pid^1, 0, &mbufs[i], 1);
        } else {
          dpdk::hexdump_mbuf(stdout, mbufs[i]);
          rte_pktmbuf_free(mbufs[i]);
        }
      } // for
#endif
    }
  }
}



int main(int argc, char** argv)
{
  ssn_log_set_level(SSN_LOG_DEBUG);
  ssn_init(argc, argv);
  ssn_green_thread_sched_register(1);

  const size_t nb_ports = ssn_dev_count();
  if (nb_ports != 2) {
    std::string err = slankdev::format(
        "n_ports is not 2, (n_port=%zd)", nb_ports);
    throw slankdev::exception(err.c_str());
  }

  ssn_port_conf conf;
  for (size_t i=0; i<nb_ports; i++) {
    ssn_port_configure(i, &conf);
    ssn_port_dev_up(i);
    ssn_port_promisc_on(i);
  }

  acl_5tuple acl;
  // acl.add_rule(1, 1, 1, 0x01,
  //     0x00000000,  0, 0x00000000, 0,
  //     0x0000, 0xffff, 0x0000, 0xffff);
  acl.add_rule(2, 1, 2, 0x11,
      0xc0a80000, 16, 0xc0a80300, 24,
      0xeeee, 0xeeee, 0x0000, 0xffff);
  acl.build();

  printf("\n\n");
  ssn_native_thread_launch(acl_filter, &acl, 2);
  while (1) {
    char c = getchar();
    if (c == 'q') break;
  }
  running = false;

  ssn_green_thread_sched_unregister(1);
  ssn_wait_all_lcore();
  ssn_fin();
}


