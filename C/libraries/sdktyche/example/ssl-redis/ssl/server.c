#include "config.h"
#include "ssl_redis_app.h"
#include "sdk_tyche_rt.h"

#include "help.h"

ssl_channel_t *ssl = NULL;
redis_channel_t *redis = NULL;

static char to_redis_buffer[MSG_BUFFER_SIZE] = {0};
static char to_outside_buffer[MSG_BUFFER_SIZE] = {0};

// ——————————————————— Declare the ring buffer functions ———————————————————— //

RB_DECLARE_FUNCS(char);

// —————————————————————————————— SLL Workers ——————————————————————————————— //

/// The bear ssl API expects this to block until at least one byte is read.
/// We will read more than that if we're given the chance.
/// We also only call this function if a previous check on the channel said
/// that it was not empty.
int read_worker(void* ctx, unsigned char* buf, size_t len) {
  int read = 0;
  //This is a read alias from to ssl->request.
  if (((rb_char_t*) ctx) != &(ssl->request)) {
    // Bear ssl has tricked us or we miss-configured it.
    suicide();
  }
  // This should never be called if the channels is empty.
  if (rb_char_is_empty(&(ssl->request))) {
    suicide();
  }
  // The buffer cannot be NULL.
  if (buf == NULL) {
    suicide();
  }
  // Now at least one byte must be read (this is all encrypted data).
  // Don't get confused, I wrote the code as if we were looking to read
  // more up to len bytes, but it actually bails as soon as read > 0.
  while (read == 0) {
    int res = rb_char_read_alias_n(&(ssl->request), ssl->request_buffer, len - read, &buf[read]);
    if (res == FAILURE) {
      // Something went very wrong.
      suicide();
    }
    // For the moment let's be chill and bail as soon as we have something.
    read += res;
  }
  return read;  
}


/// The bear ssl API expects this to block until at least one byte is written.
/// We should only call this if a previous check on the channel said it was not full.
/// We block until we're able to flush the entire buffer because bear is just 
/// going to keep asking us to do so.
int write_worker(void* ctx, const unsigned char* buf, size_t len) {
  int written = 0;
  //This is a write alias to ssl->response.
  if (((rb_char_t*) ctx) != &(ssl->response)) {
    // Bear ssl has tricked us or we miss-configured it.
    suicide();
  }
  // This should never be called if the channels is full.
  if (rb_char_is_full(&(ssl->response))) {
    suicide();
  }
  // The buffer cannot be NULL.
  if (buf == NULL) {
    suicide();
  }
  // Now at least one byte must be written (this is all encrypted data).
  // We have a choice here, we could bail early or flush the bytes.
  // The drainer is the outside enclaves, the data has been read from to_redis->response
  // and is currently sitting in a buffer inside bear.
  // It will probably attempt to write it all so we might as well keep going.
  while (written < len) {
    int res = rb_char_write_alias_n(&(ssl->response), ssl->response_buffer, len - written, (char*) &buf[written]);
    if (res == FAILURE) {
      // Something went very wrong.
      suicide();
    }
    written += res;
  }
  return written; 
}

// ————————————————————————————— The main logic ————————————————————————————— //


// Declare this outside to avoid stack overflow.
static char buffer[MSG_BUFFER_SIZE] = {0};

static void run_ssl(void) {
  // Initialize bear context;
  ssl_context_t ssl_ctxt = {0};
  ssl_ctxt.read_chan = &(ssl->request);
  ssl_ctxt.write_chan = &(ssl->response);
  if (init_bear(&ssl_ctxt, read_worker, write_worker) != SUCCESS) {
    // Something went wrong.
    suicide();
  }

  // Implement a busy poll/select.
  // Start by draining shared queues then moving stuff around.
  while (1) {
    // We have some input to decrypt and enqueue to_redis.
    if (!rb_char_is_empty(&(ssl->request))) {
      // Check we have some room for redis rquests.
      int count = redis->request.capacity - rb_char_get_count(&(redis->request));
      if (count > 0) {
        int written = 0;
        int read = br_sslio_read(&(ssl_ctxt.io), buffer, count);
        if (read < 0) {
          // Client dropped apparently.
          suicide();
        }
        written = rb_char_write_n(&(redis->request), read, buffer);
        if (written != read) {
          // That's not normal, we checked there was enough room.
          suicide();
        }
      }
    }

    // We have some input to encrypt and enqueue to_outside.
    if (!rb_char_is_empty(&(redis->response))) {
      // Check we have room write the response to the outside.
      int count = ssl->response.capacity - rb_char_get_count(&(ssl->response));
      if (count > 0) {
        int read = rb_char_read_n(&(redis->response), count, buffer);
        if (read < 0) {
          // Something went wrong.
          suicide();
        }
        if (br_sslio_write_all(&(ssl_ctxt.io), buffer, read) < 0) {
          // Something went wrong.
          suicide();
        }
      }
    }
  }
failure:
  // Something went wrong, crash.
  suicide();
}

void trusted_entry(void) {
  ssl = (ssl_channel_t *)SSL_VIRT_ADDRESS;
  redis = (redis_channel_t *)REDIS_PIPE_ADDRESS;
  run_ssl();
}
