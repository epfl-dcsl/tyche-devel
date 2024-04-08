#include <asm-generic/errno.h>
#include <errno.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"
#include "common_log.h"
#include "ssl_redis_app.h"
#include "ringbuf_generic.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>

// —————————————————————————————— Local types ——————————————————————————————— //

typedef struct thread_arg_t {
  // Client socket.
  int socket;
  // the redis_app info
  ssl_channel_t* app;
} thread_arg_t;

// Function to handle each client connection
void *tcp_connection_handler(void *arg) {
  thread_arg_t *arguments = (thread_arg_t*) arg;
  int new_socket = arguments->socket;
  char buffer[NET_BUFFER_SIZE] = {0};

  // Set client socket to non-blocking mode
  //int flags = fcntl(new_socket, F_GETFL, 0);
  //fcntl(new_socket, F_SETFL, flags | O_NONBLOCK);
  LOG("Started a TCP connexion handler for a client.");

  while(1) {
    int written = 0;
    int read = recv(new_socket, buffer, NET_BUFFER_SIZE, MSG_DONTWAIT);
    if (read < 0) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        ERROR("Something went wrong with the socket");
        exit(-1);
      }
      goto try_read;
    }
    if (read == 0) {
      goto try_read;
    }
    // We have some things to transmit to ssl.
    written = rb_char_write_n(&(arguments->app->request), read, buffer);
    if (written == FAILURE || written != read) {
      if (written == FAILURE) {
        ERROR("Failure on write channel");
        exit(-1);
      }
      ERROR("failed to write everything to ssl %d, expected %d | %d is full",
          written, read, rb_char_is_full(&(arguments->app->request)));
      exit(-1);
    }

try_read:
    written = 0;
    read = rb_char_read_n(&(arguments->app->response), MSG_BUFFER_SIZE, buffer);
    if (read == FAILURE) {
      ERROR("Error reading from ssl");
      exit(-1);
    }
    while (written < read) {
      int res = write(new_socket, buffer, read - written);
      if (res < 0) {
        ERROR("Failed to write back the response");
        exit(-1);
      }
      written += res;
    }
  }
  return NULL;
}

int tcp_start_server(usize core, ssl_channel_t* comm) {
  int server_fd, new_socket;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);

  // Creating socket file descriptor
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  // Forcefully attaching socket to the port 8080
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                 sizeof(opt))) {
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(NET_PORT);

  // Forcefully attaching socket to the port 8080
  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }
  if (listen(server_fd, 3) < 0) {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  // Accept connections and handle each in a new thread
  LOG("Started TCP server on %d", NET_PORT);
  if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                           (socklen_t *)&addrlen)) < 0) {
    ERROR("Failed accept");
    return FAILURE;
  }
  pthread_t thread;
  thread_arg_t* args = malloc(sizeof(thread_arg_t*));
  if (args == NULL) {
    ERROR("Unable to allocate arguments for the connection handler threads.");
    exit(-1);
  }
  // Setup the arguments for tcp.
  args->socket = new_socket;
  args->app = comm;

  tcp_connection_handler((void*) args);
  LOG("Returned from handling client");
  free(args);
  close(server_fd);
  return SUCCESS;
}
