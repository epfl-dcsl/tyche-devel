#include <stddef.h>
#include "ringbuf.h"

// ———————————————————————————— Local functions ————————————————————————————— //

static inline void buff_index_store(buff_index_t* dest, buff_index_t value) {
#ifdef RB_NO_ATOMICS
	*dest = value;
#else
	atomic_store(dest, value);
#endif
}

static inline buff_index_t buff_index_load(buff_index_t *src) {
#ifdef RB_NO_ATOMICS
	return *src;
#else
	return atomic_load(src);
#endif
}

static inline void buff_index_incr(buff_index_t* dest) {
#ifdef RB_NO_ATOMICS
	*dest += 1;
#else
	atomic_fetch_add(dest, 1);
#endif
}

static inline void buff_index_decr(buff_index_t *dest) {
#ifdef RB_NO_ATOMICS
	*dest -= 1;
#else
	atomic_fetch_sub(dest, 1);
#endif
}

// —————————————————————————————————— API ——————————————————————————————————— //

int ringbuf_init(ringbuf_t* rb, int capacity, usize* buff) {
	if (rb == NULL || capacity < 0 || buff == NULL) {
		goto failure;
	}
	rb->capacity = capacity;
	rb->head = 0;
	rb->tail = 0;
	rb->count = 0;
	rb->buffer = buff;
	return SUCCESS;
failure:
	return FAILURE;
}

int ringbuf_write(ringbuf_t* rb, void* elem) {
	if (rb == NULL || elem == NULL) {
		goto failure;
	}
	if (ringbuf_is_full(rb)) {
		goto failure;
	}
	rb->buffer[rb->tail] = (usize) elem;
	rb->tail = (rb->tail + 1) % rb->capacity;
	buff_index_incr(&(rb->count));
	return SUCCESS;
failure:
	return FAILURE;
}

int ringbuf_read(ringbuf_t* rb, usize* addr_result) {
	if (rb == NULL || addr_result == NULL) {
		goto failure;
	}
	// check if is empty.
	if (ringbuf_is_empty(rb)) {
		goto failure;
	}
	*addr_result = rb->buffer[rb->head];
	rb->head = (rb->head + 1) % rb->capacity; 
	buff_index_decr(&(rb->count));
	return SUCCESS;
failure:
	return FAILURE;
}

int ringbuf_is_empty(ringbuf_t *rb) {
	if (rb == NULL) {
		return 1;
	}
	if (buff_index_load(&(rb->count)) == 0) {
		return 1;
	}
	return 0;
}

int ringbuf_is_full(ringbuf_t *rb) {
	if (rb == NULL) {
		return 1;
	}
	if (buff_index_load(&(rb->count)) == rb->capacity) {
		return 1;
	}
	return 0;
}
