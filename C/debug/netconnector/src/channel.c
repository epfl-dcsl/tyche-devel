#include <stdatomic.h>
#include <string.h>
#include <stdlib.h>
#include "channel.h"

/// Write to the channel
int channel_write(channel_t* chan, char* msg, size_t size) {
	int expected = EMPTY;
	if (chan == NULL || msg == NULL || size == 0 || size > BUFFER_SIZE) {
		return -1;
	}
	if (size > BUFFER_SIZE) {
		return -1;
	} 
	while (atomic_load(&(chan->written)) != CLOSED &&
				atomic_load(&(chan->written)) != EMPTY) {}

	// The channel is free.
	memcpy(chan->buffer, msg, size);
	chan->msg_size = size;
	atomic_store(&(chan->written), FULL);
	return 0;
}

/// Read from the channel
size_t channel_read(channel_t* chan, char** msg) {
	size_t rd_size = 0;
	if (chan == NULL || msg == NULL) {
		return 0;
	}
	while(atomic_load(&(chan->written)) != CLOSED && atomic_load(&(chan->written)) != FULL) {}
	if (chan->written == CLOSED) {
		// bail
		return 0;
	}
	*msg = malloc(chan->msg_size);
	if (*msg == NULL) {
		return 0;
	}
	memcpy(*msg, chan->buffer, chan->msg_size);
	rd_size = chan->msg_size;
	chan->msg_size = 0;
	atomic_store(&(chan->written), EMPTY);
	return rd_size; 
}
