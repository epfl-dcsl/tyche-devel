#pragma once

#include "common.h"
#include "ringbuf_generic.h"
#include <stdatomic.h>

RB_DECLARE_ALL(char);

#define MSG_BUFFER_SIZE 1048

typedef enum enclave_status_t {
	BOOT = 0,
	IN_MAIN = 111,
	POST_INIT = 2,
	IN_LOOP = 3,
	DONE_SUCCESS = 4,
	DONE_ERROR = 5,
} enclave_status_t;

typedef struct info_t {
	enclave_status_t status;
	void* channel;
	int msg_size;
	char msg_buffer[1048];
} info_t;

typedef enum PING_PONG_STATE_T {
	NOT_READY = 0,
	READY = 0x777,
} PING_PONG_STATE_T;

typedef struct ping_pong_t {
	/// Signals that the channel has been initialized by ping.
	atomic_int ready;
	/// The communication ringbuffer.
	rb_char_t rb;
	/// The actual buffer for communications.
	char buffer[MSG_BUFFER_SIZE];
} ping_pong_t;
