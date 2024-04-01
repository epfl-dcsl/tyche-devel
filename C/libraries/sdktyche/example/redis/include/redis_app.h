#pragma once

#include "common.h"
#include "ringbuf_generic.h"

// ——————————————————— Type for the shared memory region ———————————————————— //

RB_DECLARE_TYPE(char);
RB_DECLARE_PROTOS(char);

#define MSG_BUFFER_SIZE 1048

/// The redis enclave shared memory gets typecasted to this.
typedef struct redis_app_t {
	// Sending things to redis.
	rb_char_t to_redis;
	// Receiving messages from redis.
	rb_char_t from_redis;
	// Buffer for the to_redis.
	char to_buffer[MSG_BUFFER_SIZE];
	// Buffer for the from_redis.
	char from_buffer[MSG_BUFFER_SIZE];
} redis_app_t;

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
int tcp_start_server(usize core, redis_app_t* comm);

/// The main runner for a single connection.
void* tcp_connection_handler(void* socket_desc);

// ————————————————————————— STDIN server functions ————————————————————————— //

/// Simple stdin server.
int stdin_start_server(usize core, redis_app_t* comm);
