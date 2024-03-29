#pragma once

#include "common.h"

#ifdef RB_NO_ATOMICS
typedef int buff_index_t;
#else
#include <stdatomic.h>
typedef atomic_int buff_index_t;
#endif

// ————————————————————————————————— Types —————————————————————————————————— //

typedef struct ringbuf_t {
	// The number of cells inside the ring buffer;
	int capacity;
	// The number of items inside the buffer.
	buff_index_t count;
	// The head (read) of the ring buffer.
	buff_index_t head;
	// The tail (write) of the ring buffer.
	buff_index_t tail;
	// Array of pointers to allocated elements.
	usize* buffer;
} ringbuf_t;

// —————————————————————————————————— API ——————————————————————————————————— //

/// Initialize the ring buffer with capacity and buffer.
/// Returns FAILURE if rb is NULL, buff is NULL, or capacity is < 0.
/// Returns SUCCESS otherwise.
int ringbuf_init(ringbuf_t* rb, int capacity, usize* buff);

/// Write the element inside the ring buffer.
/// Returns FAILURE if rb is NULL or elem is NULL.
/// Returns SUCCESS otherwise.
int ringbuf_write(ringbuf_t* rb, void* elem);

/// Reads from the ring buffer (sets address inside addr_result).
/// Returns FAILURE if rb is NULL or addr_result is NULL.
/// Return SUCCESS otherwise.
int ringbuf_read(ringbuf_t* rb, usize* addr_result);

/// Checks whether the buffer is empty.
/// If rb is NULL, defaults to true.
int ringbuf_is_empty(ringbuf_t* rb);

/// Checks whether the buffer is full.
/// If rb is NULL, defaults to true.
int ringbuf_is_full(ringbuf_t* rb);

// ————————————————————— Generic interface for ringbuf —————————————————————— //
#define DECLARE_RB_TYPE(elem_type, write_name, read_name) \
	static int write_name(ringbuf_t* rb, elem_type* elem)   \
	{                                                       \
		return ringbuf_write(rb, (void*)elem);                \
	}                                                       \
	static int read_name(ringbuf_t* rb, elem_type** dest)   \
	{                                                       \
		usize addr = 0;                                       \
		int res = ringbuf_read(rb, &addr);                    \
		if (res == FAILURE) {                                 \
			return FAILURE;                                     \
		}                                                     \
		*dest = (elem_type*)(addr);                           \
		return res;                                           \
	}
