
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <ndpi_main.h>

inline void* safe_malloc(size_t size)
{
  uint8_t* ret = (uint8_t*)::malloc(size);
  if (!ret) {
    throw slankdev::exception("malloc");
  }
  return ret;
}
inline void* safe_calloc(size_t nmemb, size_t size)
{
  uint8_t* ret = (uint8_t*)::calloc(nmemb, size);
  if (!ret) {
    throw slankdev::exception("calloc");
  }
  return ret;
}

/* id tracking */
struct osdpi_id {
  u_int8_t ip[4];
  struct ndpi_id_struct *ndpi_id;

  osdpi_id() :
    ndpi_id(nullptr)
  {
    const u_int32_t size_id_struct   = ndpi_detection_get_sizeof_ndpi_id_struct();
    ndpi_id = (struct ndpi_id_struct*)safe_calloc(1, size_id_struct);
  }
  virtual ~osdpi_id() { free(ndpi_id); }
  osdpi_id(const osdpi_id& rhs)
  {
    ip[0] = rhs.ip[0];
    ip[1] = rhs.ip[1];
    ip[2] = rhs.ip[2];
    ip[3] = rhs.ip[3];
    const u_int32_t size_id_struct   = ndpi_detection_get_sizeof_ndpi_id_struct();
    ndpi_id = (struct ndpi_id_struct*)safe_calloc(1, size_id_struct);
  }
};

/* flow tracking */
struct osdpi_flow {
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int8_t  protocol;
  struct ndpi_flow_struct *ndpi_flow;
  u_int32_t detected_protocol;

  osdpi_flow() :
    lower_ip(0), upper_ip(0),
    lower_port(0), upper_port(0),
    protocol(0), ndpi_flow(nullptr),
    detected_protocol(0)
  {
    const u_int32_t size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();
    ndpi_flow = (struct ndpi_flow_struct*)safe_calloc(1, size_flow_struct);
  }
  virtual ~osdpi_flow()
  {
    free(ndpi_flow);
  }
  osdpi_flow(const osdpi_flow& rhs)
  {
    lower_ip          = rhs.lower_ip;
    upper_ip          = rhs.upper_ip;
    lower_port        = rhs.lower_port;
    upper_port        = rhs.upper_port;
    protocol          = rhs.protocol;
    detected_protocol = rhs.detected_protocol;

    const u_int32_t size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();
    ndpi_flow = (struct ndpi_flow_struct*)safe_calloc(1, size_flow_struct);
  }

};
