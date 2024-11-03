#include <stdint.h>


/* A simple buffer */
typedef struct buf_t {
  uint8_t *data;
  int len;
} buf_t;


/**
 * Pops data & returns amount popped, storing data in data argument
 *
 * If data is NULL, performs the same operation, but does not attempt to store
 * anything in data.
 */
int pop(buf_t *buf, uint8_t **data, int len);

/**
 * Retrieves byte at a specific index.
 *
 * Undefined behavior if not 0 <= i < buf->len
 */
uint8_t get(const buf_t *buf, int i);

/**
 * Sets len bytes of data starting at index i to be equal to the first len
 * bytes of the data in the data argument.
 *
 * The buffer will be resized as needed if i + len > buf->len.
 */
int set(buf_t *buf, int i, const uint8_t *data, int len);

