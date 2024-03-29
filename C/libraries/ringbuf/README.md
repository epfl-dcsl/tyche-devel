# Ringbuf

A generic implementation of ring buffers.
The ring buffers are non-locking single-read/single-writer.
By default, they assume that the reader and writer are in separate threads and uses atomic operations to synch between the two.
If this is not the case, you can supply `-DRB_NO_ATOMICS` to avoid the atomic operations.

To start using the library, use the macro:

```
RB_DECLARE_ALL(TYPE)
```
This will create the following types and functions:

```
// The ring buffer for this type.
rb_TYPE_t

// Init function.
int rb_TYPE_init(rb_TYPE_t *rb, int capacity, TYPE* buffer);

// Check if buffer is full.
int rb_TYPE_is_full(rb_TYPE_t *rb);

// Check if buffer is empty.
int rb_TYPE_is_empty(rb_TYPE_t *rb);

// Write to the buffer.
int rb_TYPE_write(rb_TYPE_t *rb, TYPE elem);

// Read from the buffer.
int rb_TYPE_read(rb_TYPE_t *rb, TYPE* result);

```

An example can be found with `TYPE = int` in `tests/main.c`.
