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
#include <errno.h>

#include "common.h"
#include "common_log.h"
#include "redis_app.h"
#include "ringbuf_generic.h"

// —————————————————————————————— Local types ——————————————————————————————— //

typedef struct thread_arg_t {
  // Client socket.
  int socket;
  // Pointer to the mutex for the channel.
  pthread_mutex_t *mutex;
  // the redis_app info
  redis_app_t* app;
} thread_arg_t;

// Function to handle each client connection
void *tcp_connection_handler(void *arg) {
  thread_arg_t *arguments = (thread_arg_t*) arg;
  int new_socket = arguments->socket;
  char buffer[NET_BUFFER_SIZE] = {0};
  ssize_t valread;
  pthread_t reader;

  LOG("Started a TCP connexion handler for a client");
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
    written = rb_char_write_n(&(arguments->app->to_redis), read, buffer);
    if (written == FAILURE || written != read) {
      if (written == FAILURE) {
        ERROR("Failure on write channel");
        exit(-1);
      }
      ERROR("failed to write everything to ssl %d, expected %d | %d is full",
          written, read, rb_char_is_full(&(arguments->app->to_redis)));
      return NULL;
    }
    LOG("Wrote %d bytes on the ssl request", written);

try_read:
    written = 0;
    read = rb_char_read_n(&(arguments->app->from_redis), MSG_BUFFER_SIZE, buffer);
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

  // Previous implementation that was blocking.
  /*
  while ((valread = read(new_socket, buffer, NET_BUFFER_SIZE)) > 0) {
    // Lock the channels.
    pthread_mutex_lock(arguments->mutex);
    //TODO: let's figure things out to have the size.
    int res = rb_char_write_n(&(arguments->app->to_redis), valread, buffer);
    if (res == FAILURE || res != valread) {
        ERROR("Could not write everything to redis");
        pthread_mutex_unlock(arguments->mutex);
        goto finish;
    }

    // Now read the reply.
    do {
      res = rb_char_read_n(&(arguments->app->from_redis), MSG_BUFFER_SIZE, buffer); 
      if (res == FAILURE) {
        ERROR("Error reading from redis");
        pthread_mutex_unlock(arguments->mutex);
        goto finish;
      }
    } while(res == 0);

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
  }*/

finish:
  close(new_socket);
  free(arguments);
  pthread_exit(NULL);
}

int tcp_start_server(usize core, redis_app_t* comm) {
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
    thread_arg_t* args = malloc(sizeof(thread_arg_t));
    if (args == NULL) {
      ERROR("Unable to allocate thread args.");
      close(new_socket);
      exit(-1);
    }
    args->socket = new_socket;
    args->mutex = &mutex;
    args->app = comm;


    // Allow only a single client.
    tcp_connection_handler((void*) args);
    LOG("Client disconnected");
    break;
    /*if (pthread_create(&thread, NULL, tcp_connection_handler, (void *)args) <
        0) {
      perror("pthread_create");
      free(args);
      close(new_socket);
      continue;
    }

    // Detach the thread, so its resources are automatically released when it
    // finishes
    pthread_detach(thread);*/
  }
  close(server_fd);
}
