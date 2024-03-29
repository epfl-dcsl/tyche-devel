#pragma once

#include "common.h"

// —————————————— Helper functions for atomics vs non-atomics ——————————————— //

#ifdef RB_NO_ATOMICS
typedef int buff_index_t;
#else
#include <stdatomic.h>
typedef atomic_int buff_index_t;
#endif

// ——————————————————————————————— Functions ———————————————————————————————— //

static inline void buff_index_store(buff_index_t *dest, buff_index_t value) {
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

static inline void buff_index_incr(buff_index_t *dest) {
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

// ——————————————————————— Ring Buffer Implementation ——————————————————————— //

/// Declares a ring buffer of type elem_type.
/// capacity: the number of cells inside the buffer.
/// count: the number of items present inside the buffer.
/// head: read cell.
/// tail: write cell.
/// buffer: the user-supplied buffer to hold `capacity` values of type
/// elem_type.
#define RB_DECLARE_TYPE(elem_type)                                             \
  typedef struct rb_##elem_type##_t {                                          \
    int capacity;                                                              \
    buff_index_t count;                                                        \
    buff_index_t head;                                                         \
    buff_index_t tail;                                                         \
    elem_type *buffer;                                                         \
  } rb_##elem_type##_t;

/// Initialize the ring buffer with capacity and buffer.
/// Returns FAILURE if rb is NULL, buff is NULL, or capacity is < 0.
/// Returns SUCCESS otherwise.
#define RB_DECLARE_INIT(elem_type)                                             \
  int rb_##elem_type##_init(rb_##elem_type##_t *rb, int capacity,              \
                            elem_type *buff) {                                 \
    if (rb == NULL || capacity < 0 || buff == NULL) {                          \
      goto failure;                                                            \
    }                                                                          \
    rb->capacity = capacity;                                                   \
    rb->head = 0;                                                              \
    rb->tail = 0;                                                              \
    rb->count = 0;                                                             \
    rb->buffer = buff;                                                         \
    return SUCCESS;                                                            \
  failure:                                                                     \
    return FAILURE;                                                            \
  }

/// Checks whether the buffer is full.
/// If rb is NULL, defaults to true (1).
#define RB_DECLARE_IS_FULL(elem_type)                                          \
  int rb_##elem_type##_is_full(rb_##elem_type##_t *rb) {                       \
    if (rb == NULL) {                                                          \
      return 1;                                                                \
    }                                                                          \
    if (buff_index_load(&(rb->count)) == rb->capacity) {                       \
      return 1;                                                                \
    }                                                                          \
    return 0;                                                                  \
  }

/// Checks whether the buffer is empty.
/// If rb is NULL, defaults to true (1).
#define RB_DECLARE_IS_EMPTY(elem_type)                                         \
  int rb_##elem_type##_is_empty(rb_##elem_type##_t *rb) {                      \
    if (rb == NULL) {                                                          \
      return 1;                                                                \
    }                                                                          \
    if (buff_index_load(&(rb->count)) == 0) {                                  \
      return 1;                                                                \
    }                                                                          \
    return 0;                                                                  \
  }

/// Write the element inside the ring buffer.
/// Returns FAILURE if rb is NULL or buffer is full.
/// Returns SUCCESS otherwise.
/// @warning: if elem_type is a pointer type, no checks for NULL is performed.
#define RB_DECLARE_WRITE(elem_type)                                            \
  int rb_##elem_type##_write(rb_##elem_type##_t *rb, elem_type elem) {         \
    if (rb == NULL) {                                                          \
      goto failure;                                                            \
    }                                                                          \
    if (rb_##elem_type##_is_full(rb)) {                                        \
      goto failure;                                                            \
    }                                                                          \
    rb->buffer[rb->tail] = elem;                                               \
    rb->tail = (rb->tail + 1) % rb->capacity;                                  \
    buff_index_incr(&(rb->count));                                             \
    return SUCCESS;                                                            \
  failure:                                                                     \
    return FAILURE;                                                            \
  }

/// Reads from the ring buffer (sets address inside addr_result).
/// Returns FAILURE if rb is NULL, result is NULL, or buffer is empty.
/// Return SUCCESS otherwise.
#define RB_DECLARE_READ(elem_type)                                             \
  int rb_##elem_type##_read(rb_##elem_type##_t *rb, elem_type *result) {       \
    if (rb == NULL || result == NULL) {                                        \
      goto failure;                                                            \
    }                                                                          \
    if (rb_##elem_type##_is_empty(rb)) {                                       \
      goto failure;                                                            \
    }                                                                          \
    *result = rb->buffer[rb->head];                                            \
    rb->head = (rb->head + 1) % rb->capacity;                                  \
    buff_index_decr(&(rb->count));                                             \
    return SUCCESS;                                                            \
  failure:                                                                     \
    return FAILURE;                                                            \
  }

/// Helper macro to declare all the functions for a given type.
#define RB_DECLARE_ALL(elem_type)                                              \
  RB_DECLARE_TYPE(elem_type);                                                  \
  RB_DECLARE_INIT(elem_type);                                                  \
  RB_DECLARE_IS_FULL(elem_type);                                               \
  RB_DECLARE_IS_EMPTY(elem_type);                                              \
  RB_DECLARE_WRITE(elem_type);                                                 \
  RB_DECLARE_READ(elem_type);
