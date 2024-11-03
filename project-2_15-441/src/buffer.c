/**
 * @file buffer.c
 * @brief A buffer implementation.
 *
 * I will probably update this to have a circular buffer implementation
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "buffer.h"


int pop(buf_t *buf, uint8_t **data, int len) {
  if(buf->len < len) {
    if(data != NULL)
      *data = buf->data;
    return buf->len;
  }
  
  /* copy first len bytes of buf data to data arg */
  if(data != NULL) {
    *data = malloc(len);
    memcpy(*data, buf->data, len);
  }

  /* shift the buffer len bytes */
  int new_buf_len = buf->len - len;
  uint8_t *new_buf_data = malloc(new_buf_len);
  memcpy(new_buf_data, buf->data + len, new_buf_len);
  buf->data = new_buf_data;
  buf->len = new_buf_len;

  return len;
}


uint8_t get(const buf_t *buf, int i) {
  return buf->data[i];
}


int set(buf_t *buf, int i, const uint8_t *data, int len) {
  if(i + len > buf->len) {
    buf->data = realloc(buf->data, i + len);
  }

  memcpy(buf->data + i, data, len);
  return len;
}
