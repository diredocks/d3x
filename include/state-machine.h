#ifndef STATE_MACHINE_H
#define STATE_MACHINE_H

typedef enum {
  STATE_UNKNOWN = -1,
  STATE_START_SENT = 0,
  STATE_FIRST_IDENTITY_SENT = 1,
  STATE_CHALLENGE_SENT = 2,
  STATE_IDENTITY_SENT = 3,
  STATE_SUCCESS = 4,
  STATE_FAILURE_CHALLENGE = 5,
  STATE_FAILURE_KICKOFF = 6,
  STATE_FAILURE_UNKNOWN = 7,
  STATE_UPDATE_INTEGRITY = 8
} State;

int state_machine_init();
void state_machine_free();

int switch_to_state(State state);

#endif // STATE_MACHINE_H
