#pragma once

#include <stdatomic.h>

#define BUFFER_SIZE 1024

typedef enum channel_state {
	EMPTY = 0,
	FULL = 1,
	CLOSED = 2,
} channel_state;

/// Very dumb channel abstraction for ONE read ONE writter.
typedef struct channel_t {
	// 1 means there is a message pending.
	atomic_int written;
	// The buffer for the message
	char buffer[BUFFER_SIZE];
	// The message size.
	size_t msg_size;
} channel_t;

/// Write to the channel
int channel_write(channel_t* chan, char* msg, size_t size);

/// Read from the channel
size_t channel_read(channel_t* chan, char** msg);
