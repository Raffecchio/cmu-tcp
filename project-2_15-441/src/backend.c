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

#include "error.h"
#include "cmu_packet.h"
#include "cmu_tcp.h"
#include "send.h"
#include "recv.h"


#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

#include <assert.h>



/* send a packet to the destination referred to in a give nsocket. This
 * function will fill in the advertised widow.*/
ssize_t send_pkt(const cmu_socket_t *sock,
    cmu_tcp_header_t *pkt) {
  CHK_MSG("Error: Packet is too large!", get_plen(pkt) <= MAX_LEN);
  // set_advertised_window(pkt, buf_len(&(sock->window.recv_win)));
  ssize_t res = sendto(sock->socket, pkt, get_plen(pkt), 0,
        (struct sockaddr*)&(sock->conn), sizeof(sock->conn));
  return res;
}




void die_if_needed(cmu_socket_t *sock) {
  /* get death lock (NOTE: pthread_mutex_lock returns non-zero on error) */
  while (pthread_mutex_lock(&(sock->death_lock)) != 0) {}
  int death = sock->dying;  // NOTE: set to dying in cmu_close
  pthread_mutex_unlock(&(sock->death_lock));
  if(!death)
    return;
  // NOTE: At this point, since sock->dying is true, the implementation is
  // guaranteed to not add any more data to the sending buffer, so no need
  // to get a lock here
  if ((buf_len(&(sock->sending_buf)) > 0)
      // || (buf_len(&(sock->received_buf)) > 0)
      || (sock->window.last_seq_received >= sock->window.next_seq_expected)
      || (buf_len(&(sock->window.send_win)) > 0))
    return;
  pthread_exit(NULL);
}





// static int update_received_buf(cmu_socket_t *sock) {
//   /* calulate number of bytes which are available from the left of the window */
//   uint32_t pop_len = 0;
//   while((pop_len < buf_len(&(sock->window.recv_win))) &&
//       (buf_get(&(sock->window.recv_mask), pop_len) > 0))
//     pop_len++;
//   if(pop_len == 0)
//     return 0;
// 
//   /* move first pop_len bytes from window to received buf */
//   /* then resize the receive window to stay within limits */
//   uint8_t *received_data;
//   buf_pop(&(sock->window.recv_win), &received_data, pop_len);
//   while(pthread_mutex_lock(&(sock->recv_lock)) != 0) {}
//   buf_append(&(sock->received_buf), received_data, pop_len);
//   pthread_mutex_unlock(&(sock->recv_lock));
// 
//   /* shift the mask */
//   buf_pop(&(sock->window.recv_mask), NULL, pop_len);
// 
//   sock->window.next_seq_expected += pop_len;
//   return 1;
// }


void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  // loop until pthread exit
  while (1) {
    die_if_needed(sock);

    /* perform send & receive routines */
    /* receive routine, running before send routine to avoid unnecessary retransmission of
     * ACKed packets */
    const cmu_tcp_header_t *recv_pkt =
      (cmu_tcp_header_t *)chk_recv_pkt(sock, NO_WAIT);
    uint32_t num_recv = 0;
    uint32_t old_next_seq_expected = sock->window.next_seq_expected;
    if((recv_pkt != NULL) && is_valid_recv(sock, recv_pkt)) {
      num_recv = on_recv_pkt(sock, recv_pkt);
    }

    /* check for a packet to send (and, well, send) */
    cmu_tcp_header_t *pkt_send;
    pkt_send = (cmu_tcp_header_t *) chk_send_pkt(sock);
    if(pkt_send != NULL) {
      set_ack(pkt_send, sock->window.next_seq_expected);
      set_flags(pkt_send, ACK_FLAG_MASK);
      send_pkt(sock, pkt_send);
    }

    int send_dup = (sock->window.next_seq_expected == old_next_seq_expected);
    if((recv_pkt != NULL) && (get_payload_len(recv_pkt) > 0) &&
        ((pkt_send == NULL) || send_dup)) {
      /* send standalone ACK */
      cmu_tcp_header_t *pkt = get_base_pkt(sock, 0);
      set_flags(pkt, ACK_FLAG_MASK);
      set_ack(pkt, sock->window.next_seq_expected);
      send_pkt(sock, pkt);
    };
  }
  pthread_exit(NULL);
  return NULL;
}

