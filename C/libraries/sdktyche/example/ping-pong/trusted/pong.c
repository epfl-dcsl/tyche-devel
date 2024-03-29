#include "sdk_tyche_rt.h"
#include "ping_pong.h"


info_t* shared = NULL;

static void pong(void) {
	int read = 0;
	ping_pong_t* pp = (ping_pong_t*) (shared->channel);
	shared->status = IN_MAIN;
	/// Give time to the ping thread to initialize the channel.
	while(atomic_load(&(pp->ready)) != READY) {}

	// We're ready to start reading.
	while(read < shared->msg_size) {
		int res = rb_char_read_n(&(pp->rb), shared->msg_size - read, &(shared->msg_buffer[read]));
		if (res == FAILURE) {
			// Signal error to tyche.
			shared->status = DONE_ERROR;
			return;
		}
		read += res;
	}
	// We wrote everything just complete the mission.
	shared->status = DONE_SUCCESS;
}

void trusted_entry(void)
{
	shared = (info_t*) get_default_shared_buffer();
	pong();
}
