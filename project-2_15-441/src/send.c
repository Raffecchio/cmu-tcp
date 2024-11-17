#include "send.h"

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "buffer.h"
#include "cca.h"
#include "error.h"

#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

typedef cmu_tcp_header_t hdr_t;

/* adds any available bytes to the send window from the sending buffer */
static int fill_send_win(cmu_socket_t *sock) {
  uint32_t send_winlen = buf_len(&(sock->window.send_win));
  uint32_t winlen_limit = MIN(sock->window.adv_win, sock->window.cwin);
  if (send_winlen >= winlen_limit) {
    return 0;
  }

  CHK(winlen_limit >= send_winlen);

  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }
  uint32_t num_fill =
      MIN(buf_len(&(sock->sending_buf)), (winlen_limit - send_winlen));
  uint8_t *new_send_data;
  buf_pop(&(sock->sending_buf), &new_send_data, num_fill);
  pthread_mutex_unlock(&(sock->send_lock));
  buf_append(&(sock->window.send_win), new_send_data, num_fill);
  free(new_send_data);
  return 0;
}

cmu_tcp_header_t *get_base_pkt(cmu_socket_t *sock, uint16_t pl_len) {
  // uint16_t hlen = sizeof(cmu_tcp_header_t);
  // uint16_t plen = hlen + pl_len;
  // cmu_tcp_header_t* header = malloc(pkt_len);
  // set_src(header, sock->my_port);
  // set_dst(header, sock->my_port);
  // set_hlen(header, hlen);
  // set_plen(header, pkt_len);

  // set_seq(header, sock->window.last_ack_received);
  // set_ack(header, sock->window.next_seq_expected);
  // set_flags(header, 0);
  // set_advertised_window(header, buf_len(&(sock->window.recv_win)));
  // set_extension_length(header, 0);

  // return header;

  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + pl_len;
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint32_t seq = sock->window.last_ack_received;
  uint32_t ack = sock->window.next_seq_expected;
  uint8_t flags = 0;
  uint16_t advertised_window = buf_len(&(sock->window.recv_win));
  uint8_t extension_length = 0;
  return (hdr_t *)create_packet(src, dst, seq, ack, hlen, plen, flags,
                                advertised_window, extension_length, NULL, NULL,
                                pl_len);
}

/**
 * Get a packet from the send window.
 * i must be <= sock->window.num_inflight
 */
cmu_tcp_header_t *get_win_pkt(cmu_socket_t *sock, uint32_t i) {
  /* resend the leftmost bytes, up to MSS, in the window */
  uint32_t send_winlen = buf_len(&(sock->window.send_win));
  uint16_t payload_len = MIN(send_winlen - i, (uint32_t)MSS);
  cmu_tcp_header_t *pkt = get_base_pkt(sock, payload_len);
  uint8_t *payload = get_payload((uint8_t *)pkt);
  buf_get_data(&(sock->window.send_win), i, payload, payload_len);
  set_seq(pkt, sock->window.last_ack_received + i);
  /* update the last sent time */
  return pkt;
}

/**
 * Handles sending window, including actual sending, timeout, sending new data,
 * shifting window, etc.
 *
 * This function should only be called if any returned packet will be sent
 * immediately after.
 */
cmu_tcp_header_t *chk_send_pkt(cmu_socket_t *sock) {
  fill_send_win(sock);
  uint32_t send_winlen = buf_len(&(sock->window.send_win));

  /* check timeout & resend leftmost window bytes if so */
  struct timeval now;
  gettimeofday(&now, NULL);
  double elapsed_ms = (now.tv_sec - sock->window.last_send) * 1000.0;
  int timeout = (sock->window.last_send > 0) && (elapsed_ms >= DEFAULT_TIMEOUT);

  if (timeout) {
    printf("timeout!\n");
    hdr_t *pkt = get_win_pkt(sock, 0);
    sock->window.num_inflight =
        MAX(get_payload_len(pkt), sock->window.num_inflight);

    gettimeofday(&now, NULL);
    sock->window.last_send = now.tv_sec;
    cca_enter_ss_from_timeout(sock);
    return pkt;
  }

  // if(timeout || sock->window.dup_ack_cnt >= 3) {
  // // if((sock->window.num_inflight > 0)
  // //     && (sock->window.last_send >= 0)
  // //     && ((elapsed_ms >= DEFAULT_TIMEOUT)
  // //     || (sock->window.dup_ack_cnt >= 3))) {
  //   hdr_t *pkt = get_win_pkt(sock, 0);
  //   sock->window.num_inflight = MAX(get_payload_len(pkt),
  //       sock->window.num_inflight);

  //   gettimeofday(&now, NULL);
  //   sock->window.last_send = now.tv_sec;
  // if(timeout) {
  //   sock->window.dup_ack_cnt = 0;
  //   cca_enter_ss_from_timeout(sock);
  // } else {
  //   cca_dup_ack(sock);
  // }
  //   return pkt;
  // }

  /* send any data in the window that has not been made in-flight */
  uint32_t num_inflight = sock->window.num_inflight;
  if (num_inflight < send_winlen) {
    hdr_t *pkt = get_win_pkt(sock, num_inflight);
    if (num_inflight == 0) {
      gettimeofday(&now, NULL);
      sock->window.last_send = now.tv_sec;
      sock->window.dup_ack_cnt = 0;
    }
    sock->window.num_inflight += get_payload_len(pkt);
    return pkt;
  }

  return NULL;
}
