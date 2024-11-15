#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>


/* A simple buffer */
typedef struct buf_t {
  uint8_t *data;
  uint32_t len;
} buf_t;


/**
 * Copies len bytes of buffer data starting at index i into data
 */
int buf_get_data(const buf_t *buf, uint32_t i, uint8_t *data, uint32_t len);


/**
 * Pops data & returns amount popped, storing data in data argument
 *
 * If data is NULL, performs the same operation, but does not attempt to store
 * anything in data. If no data is read (return value is 0), then *data is set
 * as NULL.
 */
uint32_t buf_pop(buf_t *buf, uint8_t **data, uint32_t len);

/**
 * Retrieves byte at a specific index.
 *
 * Undefined behavior if not 0 <= i < buf->len
 */
uint8_t buf_get(const buf_t *buf, uint32_t i);


/**
 * Sets len bytes of data starting at index i to be equal to the first len
 * bytes of the data in the data argument.
 *
 * The buffer will be resized as needed if i + len > buf->len.
 */
// int buf_set_data(buf_t *buf, uint32_t i, const uint8_t *data, uint32_t len);


int buf_append(buf_t *buf, const uint8_t *data, uint32_t len);


int buf_set(buf_t *buf, uint32_t i, uint8_t val);

int buf_ensure_len(buf_t *buf, uint32_t len);

/**
 * Initializes a buffer
 */
int buf_init(buf_t *buf);

/**
 *
 */
int buf_free(buf_t *buf);


uint32_t buf_len(const buf_t *buf);

#endif
