/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))


#include <assert.h>


// #define CHK(__va_args__)\
// {\
//   if(!(__va_args__))\
//     return -1; \
// }
// 
// #define CHK_MSG(MSG, __va_args__)\
// {\
//   if(!(__va_args__)) {\
//     perror(MSG);\
//     return -1; \
//   }\
// }


static inline ssize_t send_pkt(const cmu_socket_t *sock,
    const cmu_tcp_header_t *pkt) {
  ssize_t res = sendto(sock->socket, pkt, get_plen(pkt), 0,
        (struct sockaddr*)&(sock->conn), sizeof(sock->conn));
  return res;
}


/**
 * Tells if a given sequence number has been acknowledged by the socket.
 *
 * @param sock The socket to check for acknowledgements.
 * @param seq Sequence number to check.
 *
 * @return 1 if the sequence number has been acknowledged, 0 otherwise.
*/
int has_been_acked(cmu_socket_t *sock, uint32_t seq) {
  int result;
  result = after(sock->window.last_ack_received, seq);
  return result;
}


/**
 * 
 * Checks if the socket received any data
 *
 * It first peeks at the header to figure out the length of the packet and then
 * reads the entire packet.
 * 
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 * 
 */
uint8_t* chk_recv_pkt(cmu_socket_t *sock, cmu_read_mode_t flags) {
  cmu_tcp_header_t hdr;
  uint8_t *pkt = NULL;
  
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;

  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      break;
    case TIMEOUT: {
      // Using `poll` here so that we can specify a timeout.
      struct pollfd ack_fd;
      ack_fd.fd = sock->socket;
      ack_fd.events = POLLIN;
      // Timeout after DEFAULT_TIMEOUT.
      if (poll(&ack_fd, 1, DEFAULT_TIMEOUT) <= 0) {
        break;
      }
    }
    // Fallthrough.
    case NO_WAIT:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
      return NULL;
  }
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
  }
  return pkt;
}


static cmu_tcp_header_t *blank_pkt(cmu_socket_t *sock, uint16_t pl_len) {
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


static void die_if_needed(cmu_socket_t *sock) {
  /* get death lock (NOTE: pthread_mutex_lock returns non-zero on error) */
  while (pthread_mutex_lock(&(sock->death_lock)) != 0) {}
  int death = sock->dying;  // NOTE: set to dying in cmu_close
  pthread_mutex_unlock(&(sock->death_lock));
  if(!death)
    return;
  // NOTE: At this point, since sock->dying is true, the implementation is
  // guaranteed to not add any more data to the sending buffer, so no need
  // to get a lock here
  if (buf_len(&(sock->sending_buf)) > 0)
    return;
  pthread_exit(NULL);
}


/* adds any available bytes to the send window from the sending buffer */
static void update_send_window(cmu_socket_t *sock) {
  if((buf_len(&(sock->window.send_win)) >= sock->window.send_win_cap))
    return;

  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {}
  uint32_t num_send = MIN(buf_len(&(sock->sending_buf)),
      sock->window.send_win_cap - sock->window.num_inflight);
  uint8_t *new_send_data;
  buf_pop(&(sock->sending_buf), &new_send_data, num_send);
  pthread_mutex_unlock(&(sock->send_lock));
  buf_append(&(sock->window.send_win), new_send_data, num_send);
  free(new_send_data);
}


/**
 * Handles sending window, including actual sending, timeout, sending new data,
 * shifting window, etc.
 *
 * This function should only be called if the packet will be sent immediately after.
 */
static cmu_tcp_header_t* chk_send_pkt(cmu_socket_t *sock) {
  update_send_window(sock);
  uint32_t send_winlen = buf_len(&(sock->window.send_win));

  /* check timeout & resend leftmost window bytes if so */
  struct timeval now;
  gettimeofday(&now, NULL);
  double elapsed_ms = (sock->window.last_send - now.tv_sec)*1000.0;
  if((sock->window.last_send < 0) || (elapsed_ms >= DEFAULT_TIMEOUT)) {
    /* resend the leftmost bytes, up to MSS, in the window */
    uint16_t payload_len = MIN(send_winlen, (uint32_t)MSS);
    cmu_tcp_header_t *pkt = blank_pkt(sock, payload_len);
    uint8_t *payload = get_payload((uint8_t*)pkt);
    buf_get_data(&(sock->window.send_win), 0, payload, payload_len);
    sock->window.num_inflight = MAX(payload_len, sock->window.num_inflight);

    /* update the last sent time */
    gettimeofday(&now, NULL);
    sock->window.last_send = now.tv_sec;

    return pkt;
  }

  /* send any data in the window that has not been made in-flight */
  if(sock->window.num_inflight < send_winlen) {
    uint16_t payload_len = MIN(send_winlen - sock->window.num_inflight, (uint32_t)MSS);
    cmu_tcp_header_t *pkt = blank_pkt(sock, payload_len);
    uint8_t *payload = get_payload((uint8_t*)pkt);
    buf_get_data(&(sock->sending_buf), sock->window.num_inflight, payload,
        payload_len);
    sock->window.num_inflight += payload_len;

    return pkt;
  }

  return NULL;
}


static int on_recv_ack(cmu_socket_t* sock, uint16_t dst, uint32_t ack_num) {
  (void) dst;
  /* validate */
  int ack_valid = (ack_num <=
      sock->window.last_ack_received + buf_len(&(sock->window.send_win)));
  CHK_MSG("Error: Invalid ack number in received ACK packet", ack_valid);
  if(ack_num < sock->window.last_ack_received)
    return 0;
  if(ack_num == sock->window.last_ack_received) {
    // TODO (part of fast recovery)
  }

  uint32_t num_newly_acked = ack_num - sock->window.last_ack_received;
  sock->window.last_ack_received = ack_num;

  /* shift the sending window */
  buf_pop(&(sock->window.send_win), NULL, num_newly_acked);
  return 0;
}


/**
 * @return -1 if error, 0 otherwise
 */
static int on_recv_data(cmu_socket_t* sock, uint16_t dst, uint32_t seq_num,
    const uint8_t *payload, uint16_t payload_len) {
  (void) dst;
  uint32_t last_seqnum = seq_num + payload_len;
  CHK_MSG("Error: Received data which would exceed receive window",
      last_seqnum <= sock->window.next_seq_expected + sock->window.recv_win.len);

  if(seq_num < sock->window.next_seq_expected)
    return 0;

  /* mark the recv buffer & recv mask */
  uint32_t buf_start = seq_num - sock->window.next_seq_expected;
  for(uint32_t i = 0; i < payload_len; i++) {
    buf_set(&(sock->window.recv_mask), buf_start + i, 1);
    buf_set(&(sock->window.recv_win), buf_start + i, payload[i]);
  }

  return payload_len;
}


static int update_received_buf(cmu_socket_t *sock) {
  /* calulate number of bytes which are available from the left of the window */
  uint32_t pop_len = 0;
  while((pop_len < sock->window.recv_win.len) &&
      (buf_get(&(sock->window.recv_mask), pop_len) > 0))
    pop_len++;
  if(pop_len == 0)
    return 0;

  /* move first pop_len bytes from window to received buf */
  uint32_t win_len = sock->window.recv_win.len;
  uint8_t *received_data;
  buf_pop(&(sock->window.recv_win), &received_data, pop_len);
  buf_ensure_len(&(sock->window.recv_win), win_len);
  while(pthread_mutex_lock(&(sock->recv_lock)) != 0) {}
  buf_append(&(sock->received_buf), received_data, pop_len);
  pthread_mutex_unlock(&(sock->recv_lock));

  /* shift the mask & zero out newly made space at the end */
  buf_pop(&(sock->window.recv_mask), NULL, pop_len);
  buf_ensure_len(&(sock->window.recv_win), win_len);
  for(uint32_t i = win_len - pop_len; i < win_len; i++)
    buf_set(&(sock->window.recv_mask), i, 0);

  sock->window.next_seq_expected += pop_len;
  return 1;
}


/**
 * Returns the amount of bytes of new data which was received which can fit in the window
 */
static int on_recv_pkt(cmu_socket_t *sock, const cmu_tcp_header_t *pkt) {
  uint8_t flags = get_flags(pkt);
  if(flags & ACK_FLAG_MASK) {
    CHK(on_recv_ack(sock, get_dst(pkt), get_ack(pkt)))
  }
  uint16_t payload_len = get_payload_len((uint8_t*)pkt);
  if(payload_len > 0) {
    uint32_t num_recv = on_recv_data(sock, get_dst(pkt), get_seq(pkt),
        get_payload((uint8_t*)pkt), payload_len);
    CHK(num_recv)
    return payload_len;
  }
  return 0;
}


static int is_valid_recv(const cmu_tcp_header_t* pkt) {
  // TODO (?)
  (void)pkt;
  return 1;
}


void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  // loop until pthread exit
  while (1) {
    die_if_needed(sock);

    /* perform send & receive routines */
    // die_if_needed(sock);
    /* receive routine, running before send routine to avoid unnecessary retransmission of
     * ACKed packets */
    while(1) {
      /* check for a received packet & update state accordingly */
      const cmu_tcp_header_t *recv_pkt =
        (cmu_tcp_header_t *)chk_recv_pkt(sock, NO_WAIT);
      uint32_t num_recv = 0;
      uint32_t old_next_seq_expected = sock->window.next_seq_expected;
      if((recv_pkt != NULL) && is_valid_recv(recv_pkt))
        num_recv = on_recv_pkt(sock, recv_pkt);

      /* check for a packet to send (and, well, send) */
      cmu_tcp_header_t *pkt_send =
        (cmu_tcp_header_t *)chk_send_pkt(sock);
      if(pkt_send != NULL) {
        set_ack(pkt_send, sock->window.next_seq_expected);
        set_flags(pkt_send, ACK_FLAG_MASK);
        send_pkt(sock, pkt_send);
      }

      if((num_recv > 0) &&
          ((pkt_send == NULL) ||
           (sock->window.next_seq_expected == old_next_seq_expected))) {
        /* send standalone ACK */
        cmu_tcp_header_t *pkt = blank_pkt(sock, 0);
        set_flags(pkt, ACK_FLAG_MASK);
        set_ack(pkt, sock->window.next_seq_expected);
        send_pkt(sock, pkt);
      };
    }
    if(update_received_buf(sock))
      pthread_cond_signal(&(sock->wait_cond));

    chk_send_pkt(sock);
  }
  pthread_exit(NULL);
  return NULL;
}

