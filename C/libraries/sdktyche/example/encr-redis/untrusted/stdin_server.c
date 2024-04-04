#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_log.h"
#include "encr_redis_app.h"
#include "ringbuf_generic.h"

// —————————————————————————————— Local types ——————————————————————————————— //

typedef struct thread_arg_t {
  /// the core to stick to.
  usize core;
  /// The shared info with the encryption enclave.
  encr_channel_t *comm;
} thread_arg_t;

// ——————————————————————————————— Functions ———————————————————————————————— //

void *run_output(void *arg) {
  thread_arg_t *thread_arg = (thread_arg_t *)arg;
  char buffer[MSG_BUFFER_SIZE] = {0};
  if (pin_self_to_core(thread_arg->core) != SUCCESS) {
    ERROR("Pinning output thread failed %lld", thread_arg->core);
    goto failure;
  }
  LOG("Running output thread on core %lld", thread_arg->core);
  // Keep reading the channel.
  while (1) {
    int res = rb_char_read_n(&(thread_arg->comm->response), MSG_BUFFER_SIZE,
                             buffer);
    if (res == FAILURE) {
      ERROR("Failure reading the channel.");
      goto failure;
    }
    // Print to the output.
    if (res > 0) {
      printf("stdout: ");
      fwrite(buffer, res, sizeof(char), stdout);
      printf("\n");
    }
  }
  return NULL;
failure:
  return NULL;
}

//TODO: maybe write a size or something.
static int process_input(char *input, encr_channel_t *app) {
  // Send the message to encr.
  // Do not include the \0 in this version.
  int to_write = strlen(input);
  int written = 0;
  printf("Sending `%s` to encr....", input);
  while(written < to_write) {
    int res = rb_char_write_n(&(app->request), to_write - written, &input[written]);
    if (res == FAILURE) {
      // This should not happen with the stdin_server.
      ERROR("Failed to write to the channel");
      goto failure;
    }
    written += res;
  }
  printf("DONE!\n");
  return SUCCESS;
failure:
  return FAILURE;
}

int stdin_start_server(usize core, encr_channel_t *comm) {
  // Untrusted thread for prints.
  pthread_t out_thread;
  char input[NET_BUFFER_SIZE];
  // Arguments for the output thread.
  thread_arg_t output_arg = {core, comm};

  // Create the thread for the output.
  if (pthread_create(&out_thread, NULL, run_output, (void *)&output_arg) < 0) {
    ERROR("Failed to create the output thread");
    goto failure;
  }
  while (1) {
    size_t len = 0;
    if (fgets(input, sizeof(input), stdin) == NULL) {
      // Handle error or end of file
      ERROR("Error reading input or end of file\n");
      goto failure;
    }

    // Formatting for redis.
    int backslash = strcspn(input, "\n");
    input[backslash] = '\r';
    input[backslash+1] = '\n';
    input[backslash+2] = '\0';

    // Check for exit condition
    if (strcmp(input, "exit") == 0) {
      printf("Exiting...\n");
      break;
    }
    // Process the input
    if (process_input(input, comm) != SUCCESS) {
      ERROR("Failure to process the input.");
      goto failure;
    }
  }

  /// Join on the out_thread.
  /// TODO: figure out how to signal that.
  pthread_join(out_thread, NULL);

  return SUCCESS;
failure:
  return FAILURE;
}
