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
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message(cmu_socket_t *sock, uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);
  switch (flags) {
    case ACK_FLAG_MASK: {
      uint32_t ack = get_ack(hdr);
      if (after(ack, sock->window.last_ack_received)) {
        sock->window.last_ack_received = ack;
      }
      if (get_payload_len(pkt) == 0) {
        break;
      }
    }
    default: {
      socklen_t conn_len = sizeof(sock->conn);
      uint32_t seq = sock->window.last_ack_received;

      // No payload.
      uint8_t *payload = NULL;
      uint16_t payload_len = 0;

      // No extension.
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t ack = get_seq(hdr) + get_payload_len(pkt);
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = ACK_FLAG_MASK;
      uint16_t adv_window = 1;
      uint8_t *response_packet =
          create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                        ext_len, ext_data, payload, payload_len);

      sendto(sock->socket, response_packet, plen, 0,
             (struct sockaddr *)&(sock->conn), conn_len);
      free(response_packet);

      seq = get_seq(hdr);

      if (seq == sock->window.next_seq_expected) {
        sock->window.next_seq_expected = seq + get_payload_len(pkt);
        payload_len = get_payload_len(pkt);
        payload = get_payload(pkt);

        // Make sure there is enough space in the buffer to store the payload.
        sock->received_buf =
            realloc(sock->received_buf, sock->received_len + payload_len);
        memcpy(sock->received_buf + sock->received_len, payload, payload_len);
        sock->received_len += payload_len;
      }
      }
    }
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
uint8_t* check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
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

/**
 * Checks if the socket received any data and handle received packet
 *
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 */
void check_for_data_wrapper(cmu_socket_t *sock, cmu_read_mode_t flags) {

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }

  uint8_t *pkt = check_for_data(sock, flags);
  if(pkt != NULL) {
  handle_message(sock, pkt);
  }
  free(pkt);
  pthread_mutex_unlock(&(sock->recv_lock));
}

/**
 * Breaks up the data into packets and sends a single packet at a time.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void single_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  uint8_t *msg;
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);

  int sockfd = sock->socket;
  if (buf_len > 0) {
    while (buf_len != 0) {
      uint16_t payload_len = MIN((uint32_t)buf_len, (uint32_t)MSS);

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t seq = sock->window.last_ack_received;
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = 0;
      uint16_t adv_window = 1;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t *payload = data_offset;

      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
      buf_len -= payload_len;

      while (1) {
        // FIXME: This is using stop and wait, can we do better?
        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);
        // kvl: socket information of newly received packet will be received inside check_for_data_wrapper
        check_for_data_wrapper(sock, TIMEOUT);
        if (has_been_acked(sock, seq)) {
          break;
        }
      }
      data_offset += payload_len;
    }
  }
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


// static int send_pkt(const cmu_socket_t *sock, cmu_tcp_header_t *pkt) {
//   
// }


/**
 * Handles sending window, including actual sending, timeout, sending new data,
 * shifting window, etc.
 */
static int send_routine(cmu_socket_t *sock) {
  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {}
  uint32_t sending_len = buf_len(&(sock->sending_buf));
  uint32_t send_wincap = MIN(sock->window.send_win_cap, sending_len);

  /* check timeout & resend if so */
  struct timeval now;
  gettimeofday(&now, NULL);
  double elapsed_ms = (sock->window.last_send - now.tv_sec)*1000.0;
  if((sock->window.last_send < 0) || (elapsed_ms >= DEFAULT_TIMEOUT)) {
    /* resend the leftmost bytes, up to MSS, in the window */
    uint16_t pl_len = MIN(send_wincap, (uint32_t)MSS);
    cmu_tcp_header_t *pkt = blank_pkt(sock, pl_len);
    uint8_t *payload = get_payload((uint8_t*)pkt);
    buf_get_data(&(sock->sending_buf), 0, payload, pl_len);
    sendto(sock->socket, pkt, get_plen(pkt), 0,
        (struct sockaddr*)&(sock->conn), sizeof(sock->conn));
    sock->window.send_win_len = MAX(sock->window.send_win_len, pl_len);

    /* update the last sent time */
    gettimeofday(&now, NULL);
    sock->window.last_send = now.tv_sec;
  }

  while(sock->window.send_win_len < send_wincap) {
    uint16_t pl_len = MIN(send_wincap - sock->window.send_win_len,
        (uint32_t)MSS);
    cmu_tcp_header_t *pkt = blank_pkt(sock, pl_len);
    uint8_t *payload = get_payload((uint8_t*)pkt);
    buf_get_data(&(sock->sending_buf), sock->window.send_win_len, payload,
        pl_len);
    sock->window.send_win_len += pl_len;
  }
  pthread_mutex_unlock(&(sock->send_lock));
}


static int on_recv_ack(cmu_socket_t* sock, cmu_tcp_header_t* pkt) {
  
  return 0;
}


static int on_recv_data(cmu_socket_t* sock, cmu_tcp_header_t* pkt) {
  /*  */
  return 0;
}


static int recv_routine(cmu_socket_t *sock) {
  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {}
  cmu_tcp_header_t *pkt = (cmu_tcp_header_t *)check_for_data(sock, NO_WAIT);
  pthread_mutex_unlock(&(sock->recv_lock));
  if(pkt == NULL)
    return 0;
  uint8_t flags = get_flags(pkt);
  if(flags == ACK_FLAG_MASK) {
    on_recv_ack(sock, pkt);
  } else if(on_recv_data(sock, pkt)) {
      pthread_cond_signal(&(sock->wait_cond));
  }
  return 0;
}


static int backend_routine(cmu_socket_t *sock) {
  /* check for death, in which case stop */
  /* get death lock (NOTE: pthread_mutex_lock returns non-zero on error) */
  while (pthread_mutex_lock(&(sock->death_lock)) != 0) {}
  int death = sock->dying;  // NOTE: set to dying in cmu_close
  pthread_mutex_unlock(&(sock->death_lock));
  if (death && (sock->sending_buf.len == 0)) {
    // NOTE: At this point, no more data can be added to send buffer
    // connection teardown here?
    return 0;
  }

  /* perform send & receive routines */
  send_routine(sock);
  recv_routine(sock);
  return 1;
}


void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  // loop until pthread exit
  while (backend_routine(sock)) {}
  pthread_exit(NULL);
  return NULL;
}

// OLD BACKEND CODE (in inner loop, used for taking data from send buffer & sending
  // if (buf_len > 0) {
  //   data = malloc(buf_len);
  //   memcpy(data, sock->sending_buf, buf_len);
  //   sock->sending_len = 0;
  //   free(sock->sending_buf);
  //   sock->sending_buf = NULL;
  //   // unlock send_lock
  //   pthread_mutex_unlock(&(sock->send_lock));
  //   printf("single send\n");
  //   single_send(sock, data, buf_len);
  //   free(data);
  // } else {
  //   pthread_mutex_unlock(&(sock->send_lock));
  // }


// OLD BACKEND CODE (in inner loop, used for receiving data)
  // regardless of (write) buf_len - check for data
  // no wait is of type cmu_read_mode_t, Return immediately if no data is available
  check_for_data_wrapper(sock, NO_WAIT);

  /* get receive lock */
  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {}
  int received_buf_empty = (sock->received_buf.len == 0);
  pthread_mutex_unlock(&(sock->recv_lock));

  if (!received_buf_empty) {
    // Definition: The pthread_cond_signal() call unblocks at least one of the threads that are blocked on the specified condition variable cond (if any threads are blocked on cond).
    // effectively tells cmu_read to finish up
    pthread_cond_signal(&(sock->wait_cond));
  }
  
