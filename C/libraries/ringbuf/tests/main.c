#include <stdio.h>
#include <string.h>
#include <assert.h>

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
	return 0;
}
