#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include<bearssl.h>
#include "ssl.h"

static int
sock_read(void *ctx, unsigned char *buf, size_t len)
{
	for (;;) {
		ssize_t rlen;

		rlen = read(*(int *)ctx, buf, len);
		if (rlen <= 0) {
			if (rlen < 0 && errno == EINTR) {
				continue;
			}
			return -1;
		}
		return (int)rlen;
	}
}

/*
 * Low-level data write callback for the simplified SSL I/O API.
 */
static int
sock_write(void *ctx, const unsigned char *buf, size_t len)
{
	for (;;) {
		ssize_t wlen;

		wlen = write(*(int *)ctx, buf, len);
		if (wlen <= 0) {
			if (wlen < 0 && errno == EINTR) {
				continue;
			}
			return -1;
		}
		return (int)wlen;
	}
}

/*
 * Sample HTTP response to send.
 */

void * ssl_handler(void* arg) {
		int *new_socket = (int *) arg;
		int cfd = *new_socket;
		br_ssl_server_context sc;
		unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
		br_sslio_context ioc;
		int lcwn, err;
		printf("About to handle a client\n");
		custom_server_profile(&sc, CHAIN, CHAIN_LEN, &RSA);	
		/*
		 * Set the I/O buffer to the provided array. We
		 * allocated a buffer large enough for full-duplex
		 * behaviour with all allowed sizes of SSL records,
		 * hence we set the last argument to 1 (which means
		 * "split the buffer into separate input and output
		 * areas").
		 */
		br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);

		/*
		 * Reset the server context, for a new handshake.
		 */
		br_ssl_server_reset(&sc);

		/*
		 * Initialise the simplified I/O wrapper context.
		 */
		br_sslio_init(&ioc, &sc.eng, sock_read, &cfd, sock_write, &cfd);

		/*
		 * Read bytes until two successive LF (or CR+LF) are received.
		 */
		lcwn = 0;
		for (;;) {
			unsigned char x;

			if (br_sslio_read(&ioc, &x, 1) < 0) {
				printf("Client dropped\n");
				goto client_drop;
			}
			if (x == 0x0D) {
				continue;
			}
			if (x == 0x0A) {
				if (lcwn) {
					break;
				}
				lcwn = 1;
			} else {
				lcwn = 0;
			}
			putchar(x);
			// Implement an echo server.
			br_sslio_write_all(&ioc, &x, 1);
			br_sslio_flush(&ioc);
		}
		/*
		 * Write a response and close the connection.
		 */
		br_sslio_close(&ioc);

client_drop:
	err = br_ssl_engine_last_error(&sc.eng);
	if (err == 0) {
		fprintf(stderr, "SSL closed (correctly).\n");
	} else {
		fprintf(stderr, "SSL error: %d\n", err);
	}
	close(cfd);	
	free(new_socket);
	return NULL;
}
