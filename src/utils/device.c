#include "utils/device.h"
#include "packet/packet.h"
#include "utils/log.h"

#include <net/if.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct Device g_device;

void device_send_packet(pcap_t *handle, uint8_t *packet, size_t length) {
  size_t padded_length = length;

  if (length < ETHERNET_FRAME_MIN_SIZE - CRC_SIZE) {
    padded_length = ETHERNET_FRAME_MIN_SIZE - CRC_SIZE;
  }

  uint8_t *padded_packet = calloc(1, padded_length);
  if (!padded_packet) {
    log_error("memory allocation failed for padding", NULL);
    exit(EXIT_FAILURE);
  }

  memcpy(padded_packet, packet, length);

  if (pcap_sendpacket(handle, padded_packet, padded_length) != 0) {
    log_error(pcap_geterr(handle), NULL);
    free(padded_packet);
    exit(EXIT_FAILURE);
  }

  free(padded_packet);
}

void device_set_addr(const char *interface_name) {
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    log_error("failed to create socket", NULL);
    exit(EXIT_FAILURE);
  }

  struct ifreq ifr;
  strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
  ifr.ifr_name[IFNAMSIZ - 1] = '\0';

  if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) != 0) {
    log_error("failed to get hardware address", NULL);
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
  memcpy(g_device.src_mac, mac, HARDWARE_ADDR_SIZE);

  if (ioctl(sockfd, SIOCGIFADDR, &ifr) != 0) {
    log_warn("failed to get ip address", NULL);
    strncpy(g_device.ip_addr, IP_DEFAULT, IP_ADDR_SIZE);
    close(sockfd);
    return;
  }

  char *ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
  strncpy(g_device.ip_addr, ip, IP_ADDR_SIZE);

  close(sockfd);
}

void device_set_filter(const char *filter_str) {
  struct bpf_program filter;
  pcap_compile(g_device.handle, &filter, filter_str, 1, 0);
  pcap_setfilter(g_device.handle, &filter);
  pcap_freecode(&filter);
}

void device_init(const char *interface_name) {
  char err[PCAP_ERRBUF_SIZE];
  g_device.handle = pcap_open_live(interface_name, BUFSIZ, 0, 250, err);
  if (!(g_device.handle)) {
    log_error(err, NULL);
    exit(EXIT_FAILURE);
  }

  device_set_filter("ether proto 0x888E");
  device_set_addr(interface_name);

  g_device.fd = pcap_get_selectable_fd(g_device.handle);
  if (g_device.fd < 0) {
    log_error("pcap has no selectable fd", NULL);
    exit(EXIT_FAILURE);
  }
}
