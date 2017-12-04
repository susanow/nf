

#include <slankdev/socketfd.h>
#include <slankdev/hexdump.h>
#define CNT 4

uint8_t packet[] = {

  /* ethernet header */
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x08, 0x00,

  /* ipv4 header */
  0x45,
  0x00,                         // ToS
  0x00, 0x1c,                   // totlen (20+8=28=0x1c)
  0x00, 0x00,                   // id
  0x00, 0x00,                   // fragoff
  0x40,                         // ttl
  0x01,                         // protocol
  0x00, 0x00,                   // checksum
  0x01, 0x00, 0x01, 0x01,       // src
  0x01, 0x03, 0x00, 0x01,       // dst

  /* data */
  0x6c, 0x73, 0x6e, 0x61, 0x64, 0x6b, 0x76, 0x65, // slankdev

};

int main(int argc, char** argv)
{
  if (argc < 2) {
    fprintf(stderr, "Usage: %s ifname \n", argv[0]);
    return -1;
  }

  slankdev::socketfd sock;
  sock.open_afpacket(argv[1]);

  slankdev::hexdump(stdout, packet, sizeof(packet));
  for (size_t i=0; i<CNT; i++) {
    sock.write(packet, sizeof(packet));
    // packet[14+17] ++;
  }
}


