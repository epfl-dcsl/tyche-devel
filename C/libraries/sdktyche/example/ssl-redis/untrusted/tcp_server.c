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
  // Pointer to the mutex for the channel.
  pthread_mutex_t *mutex;
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
    if (read == -1) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        ERROR("Something went wrong with the socket");
        return NULL;
      }
      goto try_read;
    }
    if (read == 0) {
      goto try_read;
    }
    LOG("Received %d bytes", read);
    // We have some things to transmit to ssl.
    written = rb_char_write_n(&(arguments->app->request), read, buffer);
    if (written == FAILURE || written != read) {
      if (written == FAILURE) {
        ERROR("Failure on write channel");
        exit(-1);
      }
      ERROR("failed to write everything to ssl %d, expected %d | %d is full",
          written, read, rb_char_is_full(&(arguments->app->request)));
      return NULL;
    }
    LOG("Wrote %d bytes on the ssl request", written);

try_read:
    written = 0;
    read = rb_char_read_n(&(arguments->app->response), MSG_BUFFER_SIZE, buffer);
    if (read == FAILURE) {
      ERROR("Error reading from ssl");
      exit(-1);
    }
    if (read > 0) {
      LOG("Read %d bytes from ssl response", read);
    }
    while (written < read) {
      int res = write(new_socket, buffer, read - written);
      if (res < 0) {
        ERROR("Failed to write back the response");
        exit(-1);
      }
      written += res;
    }
    if (read > 0) 
      LOG("Wrote %d to tcp", written);
  }

  // Previous implementation that was 1 thread per client.
  // It is blocking however and needs to be fixed.
  // For now run one client to completion.
  /*
  while ((valread = read(new_socket, buffer, NET_BUFFER_SIZE)) > 0) {
    // Lock the channels.
    pthread_mutex_lock(arguments->mutex);
    //TODO: let's figure things out to have the size.
    LOG("Writting %ld bytes into the ssl request channel.", valread);
    int res = rb_char_write_n(&(arguments->app->request), valread, buffer);
    if (res == FAILURE || res != valread) {
        ERROR("Could not write everything to redis");
        pthread_mutex_unlock(arguments->mutex);
        goto finish;
    }

    // Now read the reply.
    res = rb_char_read_n(&(arguments->app->response), MSG_BUFFER_SIZE, buffer);
    LOG("Read %d bytes", res);
    if (res == FAILURE) {
      ERROR("Error reading from ssl");
      pthread_mutex_unlock(arguments->mutex);
      goto finish;
    }

    // Unlock.
    pthread_mutex_unlock(arguments->mutex);
    int written = 0;
    int to_write = res;
    while (written < to_write) {
      int res = write(new_socket, buffer, to_write - written);
      if (res < 0) {
        ERROR("Failed to write back the response");
        goto finish;
      }
      written += res;
    }
  }

  if (valread == 0) {
    printf("Client disconnected\n");
  } else {
    perror("read");
  }

finish:
  close(new_socket);
  free(arguments);
  pthread_exit(NULL);*/
}

int tcp_start_server(usize core, ssl_channel_t* comm) {
  int server_fd, new_socket;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);
  pthread_mutex_t mutex;
  pthread_mutex_init(&mutex, NULL);

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
  while (1) {
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                             (socklen_t *)&addrlen)) < 0) {
      perror("accept");
      continue;
    }

    pthread_t thread;
    thread_arg_t* args = malloc(sizeof(thread_arg_t*));
    if (args == NULL) {
      ERROR("Unable to allocate arguments for the connection handler threads.");
      exit(-1);
    }

    // Setup the arguments for tcp.
    args->socket = new_socket;
    args->mutex = &mutex;
    args->app = comm;

    // Previous implementation with threads.
    // For now run the handler directly.
    /*if (pthread_create(&thread, NULL, tcp_connection_handler, (void *)args) <
        0) {
      perror("pthread_create");
      free(args);
      close(new_socket);
      continue;
    }*/
    tcp_connection_handler((void*) args);
    LOG("Returned from handling client");
    exit(-1);
    // Detach the thread, so its resources are automatically released when it
    // finishes
    //pthread_detach(thread);
  }
}
