#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "buffer.h"
#include "send.h"

#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))


/* adds any available bytes to the send window from the sending buffer */
static int fill_send_win(cmu_socket_t *sock) {
  if((buf_len(&(sock->window.send_win)) >= sock->window.adv_win))
    return 0;

  uint32_t send_winlen = buf_len(&(sock->window.send_win));
  CHK(sock->window.adv_win >= send_winlen)

  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {}
  uint32_t num_fill = MIN(buf_len(&(sock->sending_buf)),
      (sock->window.adv_win - sock->window.num_inflight));
  uint8_t *new_send_data;
  buf_pop(&(sock->sending_buf), &new_send_data, num_fill);
  pthread_mutex_unlock(&(sock->send_lock));
  buf_append(&(sock->window.send_win), new_send_data, num_fill);
  free(new_send_data);
  return 0;
}


cmu_tcp_header_t *get_blank_pkt(cmu_socket_t *sock, uint16_t pl_len) {
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t pkt_len = hlen + pl_len;
  cmu_tcp_header_t* header = malloc(pkt_len);
  set_src(header, sock->my_port);
  set_dst(header, ntohs(sock->conn.sin_port));
  set_hlen(header, hlen);
  set_plen(header, pkt_len);

  set_seq(header, 0);
  set_ack(header, 0);
  set_flags(header, 0);
  set_advertised_window(header, 1);
  set_extension_length(header, 0);
  return header;
}


/**
 * Handles sending window, including actual sending, timeout, sending new data,
 * shifting window, etc.
 *
 * This function should only be called if any returned packet will be sent
 * immediately after.
 */
cmu_tcp_header_t* chk_send_pkt(cmu_socket_t *sock) {
  fill_send_win(sock);
  uint32_t send_winlen = buf_len(&(sock->window.send_win));

  /* check timeout & resend leftmost window bytes if so */
  struct timeval now;
  gettimeofday(&now, NULL);
  double elapsed_ms = (sock->window.last_send - now.tv_sec)*1000.0;
  if((sock->window.last_send < 0) || (elapsed_ms >= DEFAULT_TIMEOUT)
      || (sock->window.dup_ack_cnt >= 3)) {
    /* resend the leftmost bytes, up to MSS, in the window */
    uint16_t payload_len = MIN(send_winlen, (uint32_t)MSS);
    cmu_tcp_header_t *pkt = get_blank_pkt(sock, payload_len);
    uint8_t *payload = get_payload((uint8_t*)pkt);
    buf_get_data(&(sock->window.send_win), 0, payload, payload_len);
    sock->window.num_inflight = MAX(payload_len, sock->window.num_inflight);

    /* update the last sent time */
    gettimeofday(&now, NULL);
    sock->window.last_send = now.tv_sec;
    sock->window.dup_ack_cnt = 0;

    return pkt;
  }

  /* send any data in the window that has not been made in-flight */
  if(sock->window.num_inflight < send_winlen) {
    uint16_t payload_len = MIN(send_winlen - sock->window.num_inflight, (uint32_t)MSS);
    cmu_tcp_header_t *pkt = get_blank_pkt(sock, payload_len);
    uint8_t *payload = get_payload((uint8_t*)pkt);
    buf_get_data(&(sock->sending_buf), sock->window.num_inflight, payload,
        payload_len);
    sock->window.num_inflight += payload_len;

    return pkt;
  }

  return NULL;
}

