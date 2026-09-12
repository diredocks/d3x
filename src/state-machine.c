#include "state-machine.h"
#include "crypto/aes-md5.h"
#include "packet/packet.h"
#include "packet/send.h"
#include "utils/device.h"
#include "utils/log.h"

#include <event2/event.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  State state;
  int (*trans_to_func)();
} StateTransition;

typedef struct {
  State state;
  struct Packet *pkt;
} StateMachPriv;

static StateMachPriv priv;
#define PRIV (&priv)

static struct event_base *event_base = NULL;
static struct event *event = NULL;

void state_machine_recv_cb() {
  switch (PRIV->pkt->eap_code) {
  case EAP_CODE_SUCCESS:
    switch_to_state(STATE_SUCCESS);
    break;
  case EAP_CODE_FAILURE:
    switch (PRIV->pkt->eap_type) {
    case EAP_TYPE_MD5_FAILURE:
      switch_to_state(STATE_FAILURE_CHALLENGE);
      break;
    case EAP_TYPE_KICKOFF:
      switch_to_state(STATE_FAILURE_KICKOFF);
      break;
    default:
      switch_to_state(STATE_FAILURE_UNKNOWN);
      break;
    }
    break;
  case EAP_CODE_REQUESTS:
    switch (PRIV->pkt->eap_type) {
    case EAP_TYPE_IDENTITY:
      if (PRIV->state == STATE_START_SENT) {
        switch_to_state(STATE_FIRST_IDENTITY_SENT);
        break;
      }
      switch_to_state(STATE_IDENTITY_SENT);
      break;
    case EAP_TYPE_MD5OTP:
      switch_to_state(STATE_CHALLENGE_SENT);
      break;
    default:
      log_warn("unknown eap", "type", PRIV->pkt->eap_type);
      break;
    }
    break;
  case EAP_CODE_H3C:
    switch_to_state(STATE_UPDATE_INTEGRITY);
    break;
  default:
    log_warn("unknown eap", "code", PRIV->pkt->eap_code);
    break;
  }
}

static void on_packet(u_char *user, const struct pcap_pkthdr *header,
                      const u_char *packet) {
  PRIV->pkt = (struct Packet *)packet;
  state_machine_recv_cb();
}

static void on_pcap_read(evutil_socket_t fd, short events, void *arg) {
  pcap_t *pcap = arg;
  int ret = pcap_dispatch(pcap, -1, on_packet, NULL);

  if (ret == PCAP_ERROR) {
    log_error(pcap_geterr(pcap), NULL);
    exit(EXIT_FAILURE);
  }
}

int state_machine_init() {
  if (event_base)
    return 0;

  event_base = event_base_new();
  event = event_new(event_base, g_device.fd, EV_READ | EV_PERSIST, on_pcap_read,
                    g_device.handle);
  event_add(event, NULL);
  event_base_dispatch(event_base);
  return 0;
}

void state_machine_free() {
  event_free(event);
  event_base_free(event_base);
}

static int trans_to_start_sent() {
  send_start_packet();
  return 0;
}

static int trans_to_first_identity_sent() {
  memcpy(g_default_packet.dst_mac, PRIV->pkt->src_mac, HARDWARE_ADDR_SIZE);

  char filter_str[128];
  sprintf(filter_str,
          "ether src " HARDWARE_ADDR_STR " and (ether dst " HARDWARE_ADDR_STR
          " or ether dst " HARDWARE_ADDR_STR ") and ether proto 0x888E",
          HARDWARE_ADDR_FMT(g_default_packet.dst_mac),
          HARDWARE_ADDR_FMT(g_default_packet.src_mac),
          HARDWARE_ADDR_FMT(MULTICASR_ADDR));

  send_first_identity_packet(PRIV->pkt);
  return 0;
}

static int trans_to_challenge_sent() {
  send_md5otp_packet(PRIV->pkt);
  log_info("answered challenge", NULL);
  return 0;
}

static int trans_to_identity_sent() {
  send_identity_packet(PRIV->pkt);
  log_info("answered identity", NULL);
  return 0;
}

static int trans_to_success() {
  log_info("auth success (^_^)", NULL);
  return 0;
}

static int trans_to_failure_challenge() {
  uint8_t err_msg_size = PRIV->pkt->eap_type_data[0];
  char err_msg[err_msg_size + 1];
  if (err_msg_size > 0) {
    memcpy(err_msg, (const char *)(PRIV->pkt->eap_type_data + 1), err_msg_size);
    err_msg[err_msg_size] = '\0';
    log_error(err_msg, NULL);
  }
  return 2;
}

static int trans_to_failure_kickoff() {
  log_error("server kickoff", NULL);
  return 2;
}

static int trans_to_failure_unknown() {
  log_error("unsupported eap error ", "type", PRIV->pkt->eap_type);
  return 2;
}

static int trans_to_update_integrity() {
  if (*(uint16_t *)(PRIV->pkt->eap_type_data) == 0x352b) {
    aes_md5_set_response(PRIV->pkt->eap_type_data + 2);
    log_info("integrity updated", NULL);
  }
  return 0;
}

static StateTransition transition_table[] = {
    {STATE_UNKNOWN, NULL},
    {STATE_START_SENT, trans_to_start_sent},
    {STATE_FIRST_IDENTITY_SENT, trans_to_first_identity_sent},
    {STATE_CHALLENGE_SENT, trans_to_challenge_sent},
    {STATE_IDENTITY_SENT, trans_to_identity_sent},
    {STATE_SUCCESS, trans_to_success},
    {STATE_FAILURE_CHALLENGE, trans_to_failure_challenge},
    {STATE_FAILURE_KICKOFF, trans_to_failure_kickoff},
    {STATE_FAILURE_UNKNOWN, trans_to_failure_unknown},
    {STATE_UPDATE_INTEGRITY, trans_to_update_integrity}};

int switch_to_state(State state) {
  for (int i = 0; i < sizeof(transition_table) / sizeof(StateTransition); i++) {
    if (state == transition_table[i].state) {
      if (transition_table[i].trans_to_func()) {
        log_error("failed to trans state", "state", state);
        exit(EXIT_FAILURE);
        return 1;
      }
      PRIV->state = state;
      return 0;
    }
  }

  log_warn("undefined state", "state", state);
  return 0;
}
