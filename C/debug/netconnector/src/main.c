#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "channel.h"

#define PORT 1234

void *consummer(void* channel) {
	channel_t *chan = (channel_t*) channel;
	size_t read = 0;
	char * msg = NULL;
	printf("Consummer started\n");
	while ((read = channel_read(chan, &msg)) > 0) {
		printf("channel received: %s", msg);
		free(msg);
		msg = NULL;
	} 
	printf("Exiting consumer\n");
	pthread_exit(NULL);
}

// Function to handle each client connection
void *connection_handler(void *socket_desc) {
  int new_socket = *(int *)socket_desc;
  char buffer[BUFFER_SIZE] = {0};
  ssize_t valread;
	pthread_t reader;
	channel_t *chan = NULL;

	chan = malloc(sizeof(channel_t));
	if (chan == NULL) {
		printf("Failed to create a channel.\n");
		exit(EXIT_FAILURE);
	}
	memset(chan, 0, sizeof(channel_t));

	// Create the reader thread;
	if (pthread_create(&reader, NULL, consummer, (void*) chan) < 0) {
		printf("Unable to create reader thread.\n");
		exit(EXIT_FAILURE);
	}

  while ((valread = read(new_socket, buffer, BUFFER_SIZE)) > 0) {
    printf("Received: %s\n", buffer);
		if (channel_write(chan, buffer, valread) < 0) {
			printf("Error writting to the channel.\n");
			exit(EXIT_FAILURE);
		}
		printf("Wrote to the channel.\n");
  }

  if (valread == 0) {
    printf("Client disconnected\n");
  } else {
    perror("read");
  }

  close(new_socket);
  free(socket_desc);
	pthread_join(reader, NULL);
  pthread_exit(NULL);
}

static void start_server(void) {
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
  address.sin_port = htons(PORT);

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
  while (1) {
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                             (socklen_t *)&addrlen)) < 0) {
      perror("accept");
      continue;
    }

    pthread_t thread;
    int *new_sock = malloc(sizeof(int));
    if (!new_sock) {
      perror("malloc");
      close(new_socket);
      continue;
    }
    *new_sock = new_socket;

    if (pthread_create(&thread, NULL, connection_handler, (void *)new_sock) <
        0) {
      perror("pthread_create");
      free(new_sock);
      close(new_socket);
      continue;
    }

    // Detach the thread, so its resources are automatically released when it
    // finishes
    pthread_detach(thread);
  }
}

int main() {

  start_server();

  return 0;
}
