
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct rte_mbuf;
struct rte_acl_ctx;

/*
 * Support Only 5-tuple ACL
 * - ip protocol
 * - ip src address
 * - ip dst address
 * - l4 src port
 * - l4 dst port
 */
class acl_5tuple {
  struct rte_acl_ctx* acx;
 public:
  acl_5tuple();
  virtual ~acl_5tuple();
  void add_rule(
      uint32_t userdata, uint32_t category_mask,
      uint32_t priority, uint8_t proto,
      uint32_t src_addr, uint8_t src_addr_pref,
      uint32_t dst_addr, uint8_t dst_addr_pref,
      uint16_t src_port_min, uint16_t src_port_max,
      uint16_t dst_port_min, uint16_t dst_port_max);
  void build();
  bool packet_filter_pass(rte_mbuf* mbuf);
  size_t packet_filter_bulk(rte_mbuf** mbufs, size_t n_mbufs,
      rte_mbuf** pass_mbufs, rte_mbuf** eject_mbufs);
};

