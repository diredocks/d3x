#include "crypto/crypto.h"
#include "packet/packet.h"
#include "packet/send.h"
#include "state-machine.h"
#include "utils/config.h"
#include "utils/device.h"
#include "utils/log.h"

#include <pcap/pcap.h>
#include <signal.h>

void sig_exit(int sig) {
  printf("\r");
  if (g_device.handle) {
    send_signoff_packet();
    pcap_close(g_device.handle);
  }
  log_info("bye!", NULL);
  exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    log_info("Usage: zzz [path_to_config]", NULL);
    exit(EXIT_FAILURE);
  }

  signal(SIGINT, sig_exit);
  config_init(argv[1]);
  device_init(g_config.device);
  packet_init_default();
  crypto_init();

  state_machine_init();
  switch_to_state(STATE_START_SENT);
  sig_exit(0);

  return 0;
}
