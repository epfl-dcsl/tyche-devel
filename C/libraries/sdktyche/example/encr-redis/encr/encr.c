#include "encr_redis_app.h"
#include "sdk_tyche_rt.h"

encr_channel_t *encr = NULL;
redis_channel_t *redis = NULL;

static char to_redis_buffer[MSG_BUFFER_SIZE] = {0};
static char to_outside_buffer[MSG_BUFFER_SIZE] = {0};

// ——————————————————— Declare the ring buffer functions ———————————————————— //

RB_DECLARE_FUNCS(char);

// ———————————————————————————— Helper functions ———————————————————————————— //

static void suicide() {
  int *suicide = (int *)0xdeadbabe;
  *suicide = 666;
}

static void tyche_debug(unsigned long long marker) {
  asm volatile("movq %0, %%rdi\n\t"
               "movq $10, %%rax\n\t"
               "vmcall"
               :
               : "rm"(marker)
               : "rax", "rdi", "memory");
}

typedef int (*process)(char *buffer, int size);

static int decrypter(char *buffer, int size) {
  // Nothing to do for now.
  return SUCCESS;
}

static int encrypter(char *buffer, int size) {
  // Nothing to do for now.
  return SUCCESS;
}

static int nothing(char *buffer, int size) {
  // Nothing to do for now.
  return SUCCESS;
}

// Reads as many bytes as possible from to_drain.
// Processes the result with the callback fn.
// Writes all the bytes to the to_fill channel.
// If aliases are supplied, use them instead.
int drain_process_transfer(rb_char_t *to_drain, char *alias_drain,
                           rb_char_t *to_fill, char *alias_fill, process fn) {
  int read = 0;
  int written = 0;
  char buffer[MSG_BUFFER_SIZE] = {0};
  if (to_drain == NULL || to_fill == NULL || fn == 0) {
    goto failure;
  }
  // Should not be called on empty channel.
  if (rb_char_is_empty(to_drain)) {
    goto failure;
  }
  if (alias_drain != NULL) {
    read = rb_char_read_alias_n(to_drain, alias_drain, MSG_BUFFER_SIZE, buffer);
  } else {
    read = rb_char_read_n(to_drain, MSG_BUFFER_SIZE, buffer);
  }
  if (read == FAILURE || read == 0) {
    goto failure;
  }
  if (fn(buffer, read) != SUCCESS) {
    goto failure;
  }

  // Attempt to write everything.
  while (written < read) {
    int res = 0;
    if (alias_fill != NULL) {
      res = rb_char_write_alias_n(to_fill, alias_fill, read - written,
                                  &buffer[written]);
    } else {
      res = rb_char_write_n(to_fill, read - written, &buffer[written]);
    }
    if (res == 0) {
      // The channel is full apparently. Try again.
      continue;
    }
    if (res == FAILURE) {
      // Something went wrong.
      goto failure;
    }
    written += res;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

// ————————————————————————————— The main logic ————————————————————————————— //

static void run_encr(void) {
  int written = 0;
  // Intermediary ring buffers.
  // TODO: We could skip these ultimately for performance.
  rb_char_t to_redis;
  rb_char_t to_outside;

  // Initialize the local ring buffers.
  if (rb_char_init(&to_redis, MSG_BUFFER_SIZE, to_redis_buffer) != SUCCESS) {
    suicide();
  }
  if (rb_char_init(&to_outside, MSG_BUFFER_SIZE, to_outside_buffer) !=
      SUCCESS) {
    suicide();
  }

  // Implement a busy poll/select.
  // Start by draining shared queues then moving stuff around.
  while (1) {
    // We have some input to decrypt and enqueue to_redis.
    // Careful the encr channel is aliased.
    if (!rb_char_is_empty(&(encr->request)) &&
        (drain_process_transfer(&(encr->request), encr->request_buffer,
                                &to_redis, NULL, decrypter) != SUCCESS)) {
      goto failure;
    }

    // We have some input to encrypt and enqueue to_outside.
    if (!rb_char_is_empty(&(redis->response)) &&
        (drain_process_transfer(&(redis->response), NULL, &to_outside, NULL,
                                encrypter) != SUCCESS)) {
      goto failure;
    }

    // We have some content for redis.
    if (!rb_char_is_empty(&(to_redis)) &&
        (drain_process_transfer(&(to_redis), NULL, &(redis->request), NULL,
                                nothing) != SUCCESS)) {
      goto failure;
    }

    // Forward the redis responses to the outside.
    // Careful, this is aliased!
    if (!rb_char_is_empty(&(to_outside)) &&
        (drain_process_transfer(&(to_outside), NULL, &(encr->response),
                                encr->response_buffer, nothing) != SUCCESS)) {
      goto failure;
    }
  }
failure:
  // Something went wrong, crash.
  suicide();
}

void trusted_entry(void) {
  encr = (encr_channel_t *)ENCR_VIRT_ADDRESS;
  redis = (redis_channel_t *)REDIS_PIPE_ADDRESS;
  run_encr();
}
