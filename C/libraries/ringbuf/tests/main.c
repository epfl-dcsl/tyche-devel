#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "ringbuf.h"
#include "common_log.h"

DECLARE_RB_TYPE(int, rb_write, rb_read);

static void test_add_until_full(void) {
	int capacity = 10;
	usize buffer[capacity];
	int values [capacity];
	memset(buffer, 0, sizeof(usize) * capacity);
	ringbuf_t rb;
	LOG("Starting test_add_until_full");
	ringbuf_init(&rb, capacity, buffer); 

	for (int i = 0; i < capacity; i++) {
		values[i] = i;
	}
	
	for (int i = 0; i < capacity; i++) {
		int res = rb_write(&rb, &values[i]);
		assert(res == SUCCESS);
	}

	// Now assert we fail to write another value.
	assert(rb_write(&rb, (int*) 666) == FAILURE);

	// Now read all the values.
	for (int i = 0; i < capacity; i++) {
		int *value = NULL;
		int res = rb_read(&rb, &value);
		assert(res == SUCCESS && *value == i);
	}

	// Now check we fail to read again.
	int *value = 0;
	assert(rb_read(&rb, &value) == FAILURE); 
	LOG("Done with test_add_until_full");
}

static void test_circular(void) {
	int capacity = 10;
	usize buffer[capacity];
	int values [capacity];
	memset(buffer, 0, sizeof(usize) * capacity);
	ringbuf_t rb;
	LOG("Starting test_circular");
	ringbuf_init(&rb, capacity, buffer); 

	for (int i = 0; i < capacity; i++) {
		values[i] = i;
	}
	
	for (int i = 0; i < capacity; i++) {
		int res = rb_write(&rb, &values[i]);
		assert(res == SUCCESS);
	}

	// Now assert we fail to write another value.
	assert(rb_write(&rb, (int*) 666) == FAILURE);

	// Now read half of the values.
	for (int i = 0; i < capacity/2; i++) {
		int *value = NULL;
		int res = rb_read(&rb, &value);
		assert(res == SUCCESS && *value == i);
	}

	// Write half of the values.
	for (int i = 0; i < capacity/2; i++) {
		int res = rb_write(&rb, &values[i]);
		assert(res == SUCCESS);
	}

	// Now assert we fail to write another value.
	assert(rb_write(&rb, (int*) 666) == FAILURE);

	// We should be able to read capacity values.
	for (int i = 0; i < capacity; i++) {
		int *value = NULL;
		int res = rb_read(&rb, &value);
		assert(res == SUCCESS && *value == ((i + capacity/2) % capacity));
	}

	// Now check we fail to read again.
	int *value = 0;
	assert(rb_read(&rb, &value) == FAILURE); 
	LOG("Done with test_circular");
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
	return 0;
}
