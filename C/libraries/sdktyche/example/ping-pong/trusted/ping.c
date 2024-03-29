#include "sdk_tyche_rt.h"
#include "ping_pong.h"


info_t* shared = NULL;

static void ping(void) {
	int written = 0;
	ping_pong_t* pp = (ping_pong_t*) (shared->channel);
	shared->status = IN_MAIN;
	if (rb_char_init(&(pp->rb), MSG_BUFFER_SIZE, pp->buffer) != SUCCESS) {
		// Signal some error to tyche.
		shared->status = DONE_ERROR;
		return;
	}
	atomic_store(&(pp->ready), READY);
	while(written < shared->msg_size) {
		int res = rb_char_write_n(&(pp->rb), shared->msg_size - written, &(shared->msg_buffer[written]));
		if (res == FAILURE) {
			// Signal error to tyche.
			shared->status = DONE_ERROR;
			return;
		}
		written += res;
	}
	// We wrote everything just complete the mission.
	shared->status = DONE_SUCCESS;
}

void trusted_entry(void)
{
	shared = (info_t*) get_default_shared_buffer();
	ping();
}
