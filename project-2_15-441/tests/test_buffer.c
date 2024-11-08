#include <stdio.h>
#include <buffer.h>
#include <string.h>

int main(void) {
  buf_t buf;
  buf_init(&buf);
  
  /* try adding data and then popping the entire thing */
  char *data = "Hello to the world!";
  uint32_t len = strlen(data);
  buf_append(&buf, (uint8_t*)data, len + 1);

  char win[6] = "WIN!\n";
  printf("%s", win);
  for(uint32_t i = 0; i < len; i += 3) {
    uint8_t *tmp;
    buf_pop(&buf, &tmp, 3);
    memcpy(win, tmp, 3);
    printf("%s", win);
  }
  return 0;
}
