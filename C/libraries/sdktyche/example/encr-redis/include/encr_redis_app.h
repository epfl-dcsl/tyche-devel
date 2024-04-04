#pragma once

#include "common.h"
#include "ringbuf_generic.h"

// ———————————— Communication Channels (shared memory and pipes) ———————————— //
RB_DECLARE_TYPE(char);
RB_DECLARE_PROTOS(char);

#define MSG_BUFFER_SIZE 1048

// The address at which the redis pipe is set by tychools.
#define REDIS_PIPE_ADDRESS 0x300000ULL
// The virtual address at which the encr has its shared state with tychools.
#define ENCR_VIRT_ADDRESS 0x301000ULL

/// A two way channel used:
/// 1) By the untrusted code to forward encrypted/receive encrypted request/response.
/// 2) By the encr and redis enclaves to forward/receive requests/response.
typedef struct two_way_channel_t {
  // Sending things to redis.
  rb_char_t request;
  // Receiving messages from redis.
  rb_char_t response;
  // Buffer for the to_redis.
  char request_buffer[MSG_BUFFER_SIZE];
  // Buffer for the from_redis.
  char response_buffer[MSG_BUFFER_SIZE];
} two_way_channel_t;

/// Alias for case 1) above.
typedef two_way_channel_t encr_channel_t;

/// Alias for case 2) above.
typedef two_way_channel_t redis_channel_t;

// —————————————————————————— IDs for the domains ——————————————————————————— //
typedef enum DOMAIN_IDX_E {
  ENCR_DOMAIN = 0,
  REDIS_DOMAIN = 1,
  NB_DOMAINS = 2,
} DOMAIN_IDX_E;

// —————————————————————————— Server configuration —————————————————————————— //
/// Port for the server.
#define NET_PORT 1234
/// Size of tcp buffer.
#define NET_BUFFER_SIZE 1048

// ———————————————————————————— Common functions ———————————————————————————— //
/// Helps pinning the thread to the core.
int pin_self_to_core(usize core);
// —————————————————————————— TCP server functions —————————————————————————— //
/// The server that accepts connections.
int tcp_start_server(usize core, encr_channel_t* comm);

/// The main runner for a single connection.
void* tcp_connection_handler(void* socket_desc);

// ————————————————————————— STDIN server functions ————————————————————————— //

/// Simple stdin server.
int stdin_start_server(usize core, encr_channel_t* comm);
