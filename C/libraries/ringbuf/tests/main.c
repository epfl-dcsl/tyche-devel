#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>

#include "ringbuf_generic.h"
#include "common_log.h"

RB_DECLARE_ALL(int);

RB_DECLARE_ALL(char);

static void test_add_until_full(void) {
	int capacity = 10;
	int buffer[capacity];
	memset(buffer, 0, sizeof(int) * capacity);
	rb_int_t rb;
	LOG("Starting test_add_until_full");
	rb_int_init(&rb, capacity, buffer); 

	for (int i = 0; i < capacity; i++) {
		int res = rb_int_write(&rb, i);
		assert(res == SUCCESS);
	}

	// Now assert we fail to write another value.
	assert(rb_int_write(&rb, 666) == FAILURE);

	// Now read all the values.
	for (int i = 0; i < capacity; i++) {
		int value = 0;
		int res = rb_int_read(&rb, &value);
		assert(res == SUCCESS && value == i);
	}

	// Now check we fail to read again.
	int value = 0;
	assert(rb_int_read(&rb, &value) == FAILURE); 
	LOG("Done with test_add_until_full");
}

static void test_circular(void) {
	int capacity = 10;
	int buffer[capacity];
	memset(buffer, 0, sizeof(int) * capacity);
	rb_int_t rb;
	LOG("Starting test_circular");
	rb_int_init(&rb, capacity, buffer); 

	for (int i = 0; i < capacity; i++) {
		int res = rb_int_write(&rb, i);
		assert(res == SUCCESS);
	}

	// Now assert we fail to write another value.
	assert(rb_int_write(&rb, 666) == FAILURE);

	// Now read half of the values.
	for (int i = 0; i < capacity/2; i++) {
		int value = 0;
		int res = rb_int_read(&rb, &value);
		assert(res == SUCCESS && value == i);
	}

	// Write half of the values.
	for (int i = 0; i < capacity/2; i++) {
		int res = rb_int_write(&rb, i);
		assert(res == SUCCESS);
	}

	// Now assert we fail to write another value.
	assert(rb_int_write(&rb, 666) == FAILURE);

	// We should be able to read capacity values.
	for (int i = 0; i < capacity; i++) {
		int value = 0;
		int res = rb_int_read(&rb, &value);
		assert(res == SUCCESS && value == ((i + capacity/2) % capacity));
	}

	// Now check we fail to read again.
	int value = 0;
	assert(rb_int_read(&rb, &value) == FAILURE); 
	LOG("Done with test_circular");
}

void test_byte_stream(void) {
	int capacity = 1048;	
	char buffer[capacity];
	memset(buffer, 0, capacity);
	rb_char_t rb;
	rb_char_init(&rb, capacity, buffer);
	LOG("Starting byte stream test");
	// Start by writting an entire string.
	char* message = "hello world! How are things going?\n";
	assert(rb_char_write_n(&rb, strlen(message) +1, message) == strlen(message) +1);

	// Then read the entire string back;
	char* result = malloc(strlen(message) + 1);
	assert(result != NULL);
	assert(rb_char_read_n(&rb, strlen(message)+1, result) == strlen(message) +1);
	assert(strncmp(result, message, strlen(message)) == 0);
	assert(rb_char_is_empty(&rb) == 1);
	LOG("Done with bytestream test, message is: %s", result);
}

void test_byte_stream_circular(void) {
	int capacity = 10;	
	char buffer[capacity];
	memset(buffer, 0, capacity);
	rb_char_t rb;
	rb_char_init(&rb, capacity, buffer);
	LOG("Starting byte stream circular test");
	// Start by writting 9 ones.
	char* message = "111111111";
	assert(rb_char_write_n(&rb, strlen(message), message) == strlen(message));

	// Then read 4 ones the entire string back;
	char* result = malloc(4);
	assert(result != NULL);
	assert(rb_char_read_n(&rb, 4, result) == 4);
	assert(strncmp("1111", result, 4) == 0);

	// Now we should be able to write 5 elements.
	// Attempt to write 6.
	char *one_too_many = "222222";
	assert(rb_char_write_n(&rb, 6, one_too_many) == 5);
	assert(rb_char_is_full(&rb) == 1);

	// Drain the buffer now. We should read the following.
	char* expected = "1111122222";
	free(result);
	result = NULL;
	result = malloc(capacity);
	assert(result != NULL);
	assert(rb_char_read_n(&rb, capacity, result) == capacity);
	assert(strncmp(expected, result, capacity) == 0);
	assert(rb_char_is_empty(&rb) == 1);
	LOG("Done with byte stream circular test");
}

const int MAX_RUN = 10000000;
typedef struct bench_t {
	rb_int_t* request;
	rb_int_t* response;
} bench_t;

void* spammer_handler(void* args) {
	bench_t* comm = (bench_t*) args;
	assert(comm != NULL);
	int last_value_written = 0;
	int last_value_read = 0;

	// Count from 1 to 10000, ten times the buffer capacity.
	while (last_value_read < MAX_RUN) {
		int read = 0;
		// Try to write.
		if (last_value_written < MAX_RUN &&
				rb_int_write(comm->request, last_value_written + 1) == SUCCESS) {
			last_value_written++;
		}
		if (rb_int_read(comm->response, &read) == SUCCESS) {
			assert(read == (last_value_read+1));
			last_value_read++;
		}
	}
	assert(last_value_read == last_value_written);
	assert(last_value_written == MAX_RUN);
	LOG("Spammer finished");
	return NULL;
}

void* consummer_handler(void* args) {
	bench_t* comm = (bench_t*) args;
	assert(comm != NULL);
	int last_value_written = 0;
	int last_value_read = 0;

	// Count from 1 to MAX_RUN, ten times the buffer capacity.
	while (last_value_read < MAX_RUN) {
		int read = 0;
		// Try to read
		if (rb_int_read(comm->request, &read) == SUCCESS) {
			assert(read == (last_value_read+1));
			last_value_read++;
		} else {
			// Haven't read anything yet.
			continue;
		}
		
		// Write that back forcefully.
		while (rb_int_write(comm->response, last_value_written + 1) != SUCCESS) {}
		last_value_written++;
	}
	assert(last_value_read == last_value_written);
	assert(last_value_written == MAX_RUN);
	LOG("Consummer finished.");
	return NULL;
}


void test_threads() {
	int capacity = 1000;
	pthread_t threads[2];
	bench_t *bench = malloc(sizeof(bench_t));
	rb_int_t *requests = malloc(sizeof(rb_int_t));
	rb_int_t *responses = malloc(sizeof(rb_int_t));
	int* buff_req = calloc(capacity, sizeof(int));
	int* buff_resp = calloc(capacity, sizeof(int));
	assert(requests != NULL);
	assert(responses != NULL);
	assert(buff_req != NULL);
	assert(buff_resp != NULL);
	assert(bench != NULL);
	memset(requests, 0, sizeof(rb_int_t));
	memset(responses, 0, sizeof(rb_int_t));
	memset(buff_req, 0, sizeof(int) * capacity);
	memset(buff_resp, 0, sizeof(int) * capacity);
	memset(bench, 0, sizeof(bench_t));
	assert(rb_int_init(requests, capacity, buff_req) == SUCCESS);
	assert(rb_int_init(responses, capacity, buff_resp) == SUCCESS);
	bench->request = requests;
	bench->response = responses;
	LOG("Starting thread benchmark");

	assert(pthread_create(&threads[0], NULL, spammer_handler, (void*) bench) >= 0);
	assert(pthread_create(&threads[1], NULL, consummer_handler, (void*) bench) >= 0);

	pthread_join(threads[0], NULL);
	pthread_join(threads[1], NULL);

	LOG("Done running the thread benchmark");
}

int main(void) {
	printf("Starting the test with ");
#ifdef RB_NO_ATOMICS
	printf("no atomics.\n");
#else
	printf("with atomics.\n");
#endif
	test_add_until_full();
	test_circular();
	test_byte_stream();
	test_byte_stream_circular();
	test_threads();
	return 0;
}
