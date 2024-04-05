#pragma once

#include "bearssl.h"
#include "ssl_redis_app.h"
#include <stddef.h>

// ———————————————————————————————— Defines ————————————————————————————————— //

#define CHAIN_LEN 1

// ————————————————————————————————— Types —————————————————————————————————— //
typedef struct ssl_context_t {
	// bear context: init by init_bear.
	br_ssl_server_context ctxt;
	// bear io context: init by init_bear.
	br_sslio_context io;
	// The bear buffer: set by init_bear.
	unsigned char* iobuf;
	// Read ring buffer (context): set by caller.
	rb_char_t* read_chan;
	// Write ring buffer (context): set by caller.
	rb_char_t* write_chan;
} ssl_context_t;

/// Reader/Writer type.
typedef int (*w_worker)(void* ctx, const unsigned char* buf, size_t len);
typedef int (*r_worker)(void* ctx, unsigned char* buf, size_t len);
// ——————————————————————————————— Functions ———————————————————————————————— //
int init_bear(ssl_context_t* ssl_ctxt, r_worker reader, w_worker writer);
