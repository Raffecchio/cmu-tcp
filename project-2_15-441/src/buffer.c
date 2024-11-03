/**
 * @file buffer.c
 * @brief A buffer implementation.
 *
 * I will probably update this to have a circular buffer implementation
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "buffer.h"


int buf_get_data(const buf_t *buf, uint32_t i, uint8_t *data, uint32_t len) {
  if((buf->data == NULL) || (len == 0))
    return 0;

  if(data == NULL) {
    perror("Error: cannot write to NULL data in buf_get_data");
    return -1;
  }
  if(i >= buf->len) {
    perror("Error: cannot read from large index in buf_get_data");
    return -1;
  }

  if(buf->len < i + len)
    len = buf->len - i;

  memcpy(data, buf->data + i, len);
  return 0;
}


int buf_pop(buf_t *buf, uint8_t **data, uint32_t len) {
  if(len == 0)
    return 0;

  if(buf->len <= len) {
    if(data != NULL)
      *data = buf->data;
    buf->data = NULL;
    return buf->len;
  }

  if(data != NULL) {
    /* copy first len bytes of buf data to data arg */
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


uint8_t buf_get(const buf_t *buf, int i) {
  return buf->data[i];
}


static int ensure_len(buf_t *buf, uint32_t len) {
  if(len < buf->len)
    return 0; 
  if(buf->data == NULL) {
    buf->data = malloc(len);
  } else if(buf->len) {
    buf->data = realloc(buf->data, len);
  }
  return 0;
}


int buf_set(buf_t *buf, uint32_t i, const uint8_t *data, uint32_t len) {
  if(len == 0)
    return 0;

  if(data == NULL)
    return -1;
  if(i > buf->len) {
    return -1;
  }
  
  ensure_len(buf, i + len);
  memcpy(buf->data + i, data, len);
  return len;
}


int buf_init(buf_t *buf) {
  buf->data = NULL;
  buf->len = 0;
  return 0;
}


int buf_free(buf_t *buf) {
  if(buf->data != NULL) {
    free(buf->data);
    buf->data = NULL;
  }
  buf->len = 0;
  return 0;
}

uint32_t buf_len(buf_t *buf) {
  return buf->len;
}
