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
 * This file implements the high-level API for CMU-TCP sockets.
 */

#include "cmu_tcp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>

#include "backend.h"
#include "cmu_packet.h"

#include "error.h"
#include "buffer.h"



int init_sock(cmu_socket_t *sock, const cmu_socket_type_t socket_type,
    const int port, const char *server_ip) {
  CHK_MSG("ERROR server_ip NULL", server_ip != NULL);

  sock->type = socket_type;
  sock->dying = 0;
  pthread_mutex_init(&(sock->death_lock), NULL);

  /* sending & receiving */
  buf_init(&(sock->received_buf));
  pthread_mutex_init(&(sock->recv_lock), NULL);
  buf_init(&(sock->window.recv_win));

  buf_init(&(sock->sending_buf));
  pthread_mutex_init(&(sock->send_lock), NULL);
  buf_init(&(sock->window.send_win));
  CHK_MSG("ERROR condition variable not set\n",
      pthread_cond_init(&sock->wait_cond, NULL) == 0);

  /* windowing */
  buf_init(&(sock->window.send_win));
  sock->window.adv_win = 0;
  sock->window.last_send = -1;
  sock->window.last_ack_received = 0;
  sock->window.num_inflight = 0;
  sock->window.dup_ack_cnt = 0;
  sock->window.cwin = MSS;
  buf_init(&(sock->window.recv_win));
  buf_ensure_len(&(sock->window.recv_win), MAX_NETWORK_BUFFER);
  sock->window.next_seq_expected = 0;
  sock->window.last_seq_received = 0;
  buf_init(&(sock->window.recv_mask));
  buf_ensure_len(&(sock->window.recv_mask), MAX_NETWORK_BUFFER);
  for(uint32_t i = 0; i < MAX_NETWORK_BUFFER; i++)
    buf_set(&(sock->window.recv_mask), i, 0);

  /* underlying network */
  sock->socket = socket(AF_INET, SOCK_DGRAM, 0);
  memset(&(sock->conn), 0, sizeof(sock->conn));
  sock->conn.sin_family = AF_INET;
  sock->my_port = (uint16_t)port;
  sock->conn.sin_port = htons((uint16_t)port);
  sock->ssthresh = 64000;
  sock->is_fast_recovery = 0;
  CHK_MSG("ERROR opening socket", sock->socket);
  switch (socket_type) {
    case TCP_INITIATOR:
      CHK_MSG("ERROR server_ip NULL", server_ip != NULL);
      sock->conn.sin_addr.s_addr = inet_addr(server_ip);

      struct sockaddr_in my_addr;
      my_addr.sin_family = AF_INET;
      my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
      my_addr.sin_port = 0;
      CHK_MSG("error on binding",
          bind(sock->socket, (struct sockaddr *)&my_addr, sizeof(my_addr)) >= 0);
      break;

    case TCP_LISTENER:
      sock->conn.sin_addr.s_addr = htonl(INADDR_ANY);
      int optval = 1;
      setsockopt(sock->socket, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
                 sizeof(int));
      CHK_MSG("ERROR on binding",
          bind(sock->socket, (struct sockaddr *)&(sock->conn),
            sizeof(sock->conn)) >= 0);
      break;

    default:
      perror("Unknown Flag");
      return EXIT_ERROR;
  }
  return 0;
}


static int active_connect(cmu_socket_t *sock) {
  while (1) {
    // Initiator handshake;
    size_t conn_len = sizeof(sock->conn);
    uint16_t payload_len = 0;

    /* send SYN */
    uint16_t src = sock->my_port;
    uint16_t dst = sock->my_port;
    // uint16_t dst = sock->conn.sin_port;
    struct timeval tv;
    gettimeofday(&tv,NULL);
    srand(tv.tv_usec);
    uint32_t seq_syn_sent = rand();
    printf("CLIENT init seq %d\n", seq_syn_sent);
    uint32_t ack = 0;
    uint16_t hlen = sizeof(cmu_tcp_header_t);
    uint16_t plen = hlen + payload_len;
    uint8_t flags = SYN_FLAG_MASK;
    uint16_t adv_window = CP1_WINDOW_SIZE;
    uint16_t ext_len = 0;
    uint8_t *ext_data = NULL;
    uint8_t *payload = NULL;
    uint8_t *pkt_syn =
        create_packet(src, dst, seq_syn_sent, ack, hlen, plen, flags,
                      adv_window, ext_len, ext_data, payload, payload_len);
    CHK_MSG("Error in sending SYN",
        sendto(sock->socket, pkt_syn, plen, 0, (struct sockaddr *)&(sock->conn),
           conn_len));

    /* receive SYN_ACK */
    uint8_t *pkt_syn_ack = chk_recv_pkt(sock, TIMEOUT);
    cmu_tcp_header_t *hdr_syn_ack_recv = (cmu_tcp_header_t *)pkt_syn_ack;
    flags = get_flags(hdr_syn_ack_recv);
    // received syn_ack;
    if (flags != (SYN_FLAG_MASK | ACK_FLAG_MASK))
      continue;
    int syn_ack_acked = get_ack(hdr_syn_ack_recv) == (seq_syn_sent + 1);
    if (!syn_ack_acked)
      continue;
    sock->window.last_ack_received = get_ack(hdr_syn_ack_recv);
    uint32_t seq_syn_ack_recv = get_seq(hdr_syn_ack_recv);
    sock->window.next_seq_expected = seq_syn_ack_recv + 1;
    sock->window.last_seq_received = seq_syn_ack_recv;
    printf("CLIENT Ack: sock->window.last_ack_received %d\n",
        sock->window.last_ack_received);
    printf("CLIENT: sock->window.next_seq_expected %d\n",
        sock->window.next_seq_expected);
    socklen_t conn_len_ack = sizeof(sock->conn);

    /* resize the window */
    uint32_t adv_win = get_advertised_window(hdr_syn_ack_recv);
    sock->window.adv_win = adv_win;

    /* send ACK */
    uint8_t *response_packet_ack = create_packet(
        src, dst, sock->window.last_ack_received,
        sock->window.next_seq_expected, hlen, hlen + 0,
        ACK_FLAG_MASK, adv_window, 0, NULL, NULL, 0);
    printf("%d\n", get_flags((cmu_tcp_header_t *)response_packet_ack));
    sendto(sock->socket, response_packet_ack, plen, 0,
        (struct sockaddr *)&(sock->conn), conn_len_ack);

    /* cleanup */
    free(response_packet_ack);
    free(pkt_syn_ack);
    free(pkt_syn);
    return 0;
    free(pkt_syn_ack);
  }
  return -1;
}


static int passive_connect(cmu_socket_t *sock) {
  while (1) {
    
    /* get SYN */
    uint8_t *pkt_syn_recv = chk_recv_pkt(sock, TIMEOUT);
    if(pkt_syn_recv == NULL)
      continue;
    cmu_tcp_header_t *hdr_syn_recv = (cmu_tcp_header_t *)pkt_syn_recv;
    uint32_t seq_syn_recv = get_seq(hdr_syn_recv);
    printf("SERVER orig seq from client %d\n", seq_syn_recv);
    uint8_t flags = get_flags(hdr_syn_recv);
    free(pkt_syn_recv);

    if (flags != SYN_FLAG_MASK)
      continue;
    sock->window.next_seq_expected = seq_syn_recv + 1;
    sock->window.last_seq_received = sock->window.next_seq_expected - 1;
      
    while (1) {
      // SYN_ACKING - SYN_FLAG_MASK
      size_t conn_len = sizeof(sock->conn);
      uint16_t payload_len = 0;
      uint16_t src = sock->my_port;
      uint16_t dst = sock->my_port;
      // uint16_t dst = sock->conn.sin_port;
      struct timeval tv;
      gettimeofday(&tv,NULL);
      srand(tv.tv_usec + 117);
      uint32_t seq_syn_ack_sent = 302; // rand();
      printf("SERVER orig seq sent to client %d\n", seq_syn_ack_sent);
      // uint32_t ack = seq_syn_recv + 1;
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = (SYN_FLAG_MASK | ACK_FLAG_MASK);
      uint16_t adv_window = CP1_WINDOW_SIZE;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t *payload = NULL;
      uint8_t *pkt_syn_ack_send = create_packet(
          src, dst, seq_syn_ack_sent, ack, hlen, plen, flags, adv_window,
          ext_len, ext_data, payload, payload_len);
      sendto(sock->socket, pkt_syn_ack_send, plen, 0,
             (struct sockaddr *)&(sock->conn), conn_len);
      free(pkt_syn_ack_send);
      uint8_t *pkt_ack_recv = chk_recv_pkt(sock, TIMEOUT);
      if(pkt_ack_recv == NULL)
        continue;
      cmu_tcp_header_t *hdr_two = (cmu_tcp_header_t *)pkt_ack_recv;
      int syn_ack_acked = (get_ack(hdr_two) == (seq_syn_ack_sent + 1));
      int seq_correct = (get_seq(hdr_two) == sock->window.next_seq_expected);
      if ((get_flags(hdr_two) != ACK_FLAG_MASK)
          || !syn_ack_acked
          || (get_plen(hdr_two) != hlen)
          || !seq_correct) {
        free(pkt_ack_recv);
        continue;
      }

      sock->window.last_ack_received = get_ack(hdr_two);
      sock->window.adv_win = get_advertised_window(hdr_two);
      free(pkt_ack_recv);
      return 0;
    }
    break;
  }
  return -1;
}


int cmu_socket(cmu_socket_t *sock, const cmu_socket_type_t socket_type,
               const int port, const char *server_ip) {
  init_sock(sock, socket_type, port, server_ip);

  switch (socket_type) {
    case TCP_INITIATOR:
      CHK(active_connect(sock) >= 0);
      break;

    case TCP_LISTENER:
      CHK(passive_connect(sock) >= 0);
      break;

    default:
      perror("Unknown Flag");
      return EXIT_ERROR;
  }
  struct sockaddr_in my_addr;
  socklen_t len = sizeof(my_addr);
  getsockname(sock->socket, (struct sockaddr *)&my_addr, &len);
  // on opening the socket the backend begins
  printf("beginning backend thread...\n");
  pthread_create(&(sock->thread_id), NULL, begin_backend, (void *)sock);
  return EXIT_SUCCESS;
}


int cmu_close(cmu_socket_t *sock) {
  if (sock != NULL) {
  } else {
    perror("ERROR null socket\n");
    return EXIT_ERROR;
  }

  while (pthread_mutex_lock(&(sock->death_lock)) != 0) {}
  sock->dying = 1;
  pthread_mutex_unlock(&(sock->death_lock));

  pthread_join(sock->thread_id, NULL);

  return close(sock->socket);
}


int cmu_read(cmu_socket_t *sock, void *buf, int length, cmu_read_mode_t flags) {
  int read_len = 0;

  if (length < 0) {
    perror("ERROR negative length\n");
    return EXIT_ERROR;
  }
  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {}
  uint8_t *pop_data = NULL;
  switch (flags) {
    case NO_FLAG:
      /* wait for a signal from the backend indicating recieved data */
      while (buf_len(&(sock->received_buf)) == 0)
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
    // Fall through.
    case NO_WAIT:
      read_len = buf_pop(&(sock->received_buf), &pop_data, length);
      pthread_mutex_unlock(&(sock->recv_lock));
      CHK(read_len >= 0);
      memcpy(buf, pop_data, read_len);
      break;
    default:
      perror("ERROR Unknown flag.\n");
      read_len = EXIT_ERROR;
  }
  return read_len;
}


int cmu_write(cmu_socket_t *sock, const void *buf, int length) {
  /* check if socket is dead */
  die_if_needed(sock);

  /* add the data to the sending buffer */
  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {}
  buf_append(&(sock->sending_buf), buf, length);
  pthread_mutex_unlock(&(sock->send_lock));

  return EXIT_SUCCESS;
}

