#ifndef DEVICE_H
#define DEVICE_H

#include "packet/packet.h"
#include <pcap.h>
#include <stdint.h>

struct Device {
  pcap_t *handle;
  int fd;
  char ip_addr[IP_ADDR_SIZE];
  uint8_t dst_mac[HARDWARE_ADDR_SIZE];
  uint8_t src_mac[HARDWARE_ADDR_SIZE];
};

extern struct Device g_device;

void device_send_packet(pcap_t *handle, uint8_t *packet, size_t length);
void device_set_addr(const char *interface_name);
void device_set_filter(const char *filter_str);
void device_init(const char *interface_name);

#endif // DEVICE_H
