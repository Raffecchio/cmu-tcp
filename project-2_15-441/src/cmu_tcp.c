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

#include "backend.h"
#include "cmu_packet.h"

int cmu_socket(cmu_socket_t *sock, const cmu_socket_type_t socket_type,
               const int port, const char *server_ip) {
  printf("mow");
  int sockfd, optval;
  socklen_t len;
  struct sockaddr_in conn, my_addr;
  len = sizeof(my_addr);
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    perror("ERROR opening socket");
    return EXIT_ERROR;
  }
  sock->socket = sockfd;
  sock->received_buf = NULL;
  sock->received_len = 0;
  pthread_mutex_init(&(sock->recv_lock), NULL);

  sock->sending_buf = NULL;
  sock->sending_len = 0;
  pthread_mutex_init(&(sock->send_lock), NULL);

  sock->type = socket_type;
  sock->dying = 0;
  pthread_mutex_init(&(sock->death_lock), NULL);

  // FIXME: Sequence numbers should be randomly initialized. The next expected
  // sequence number should be initialized according to the SYN packet from the
  // other side of the connection.
  sock->window.last_ack_received = 0;
  sock->window.next_seq_expected = 0;

  if (pthread_cond_init(&sock->wait_cond, NULL) != 0) {
    perror("ERROR condition variable not set\n");
    return EXIT_ERROR;
  }
  switch (socket_type) {
    case TCP_INITIATOR:
      if (server_ip == NULL) {
        perror("ERROR server_ip NULL");
        return EXIT_ERROR;
      }
      memset(&conn, 0, sizeof(conn));
      conn.sin_family = AF_INET;
      conn.sin_addr.s_addr = inet_addr(server_ip);
      conn.sin_port = htons(port);
      sock->conn = conn;

      my_addr.sin_family = AF_INET;
      my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
      my_addr.sin_port = 0;
      if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(my_addr)) < 0) {
        perror("ERROR on binding");
        return EXIT_ERROR;
      }
      // Initiator handshake;
      size_t conn_len = sizeof(sock->conn);
      uint16_t payload_len = 0;
      uint16_t src = my_addr.sin_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t seq = rand();
      uint32_t ack = 0;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = SYN_FLAG_MASK;
      uint16_t adv_window = CP1_WINDOW_SIZE;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t *payload = NULL;
      uint8_t *pkt_syn =
          create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                        ext_len, ext_data, payload, payload_len);
      while (1) {
        sendto(sockfd, pkt_syn, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);

        uint8_t *pkt_syn_ack = check_for_data(sock, TIMEOUT);
        cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt_syn_ack;
        uint8_t flags = get_flags(hdr);
        int acked = get_ack(hdr) == seq;

        if (flags == SYN_ACK_FLAG_MASK) {
          if (acked) {
            cmu_tcp_header_t *hdr_ack = (cmu_tcp_header_t *)pkt_syn_ack;
            socklen_t conn_len_ack = sizeof(sock->conn);
            uint32_t seq_ack = sock->window.last_ack_received;
            uint16_t plen_ack = hlen + 0;
            uint8_t *response_packet_ack = create_packet(
                sock->my_port, ntohs(sock->conn.sin_port), seq,
                get_seq(hdr_ack) + 1, sizeof(cmu_tcp_header_t), hlen + 0,
                ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);

            sendto(sock->socket, response_packet_ack, plen_ack, 0,
                   (struct sockaddr *)&(sock->conn), conn_len_ack);
            free(response_packet_ack);
            free(pkt_syn_ack);
            free(pkt_syn);
            break;
          }
        }
        free(pkt_syn_ack);
      }

    case TCP_LISTENER:
      memset(&conn, 0, sizeof(conn));
      conn.sin_family = AF_INET;
      conn.sin_addr.s_addr = htonl(INADDR_ANY);
      conn.sin_port = htons((uint16_t)port);

      optval = 1;
      setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
                 sizeof(int));
      if (bind(sockfd, (struct sockaddr *)&conn, sizeof(conn)) < 0) {
        perror("ERROR on binding");
        return EXIT_ERROR;
      }
      sock->conn = conn;
      while (1) {
        uint8_t *pkt_syn_recv = check_for_data(sock, TIMEOUT);

        cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt_syn_recv;
        uint32_t seq_sent = get_seq(hdr);
        uint8_t flags = get_flags(hdr);
        free(pkt_syn_recv);

        if (flags == SYN_FLAG_MASK) {
          // Initiator handshake
          size_t conn_len = sizeof(sock->conn);
          uint16_t payload_len = 0;
          uint16_t src = my_addr.sin_port;
          uint16_t dst = ntohs(sock->conn.sin_port);
          uint32_t seq = rand();
          uint32_t ack = seq_sent + 1;
          uint16_t hlen = sizeof(cmu_tcp_header_t);
          uint16_t plen = hlen + payload_len;
          uint8_t flags = SYN_ACK_FLAG_MASK;
          uint16_t adv_window = CP1_WINDOW_SIZE;
          uint16_t ext_len = 0;
          uint8_t *ext_data = NULL;
          uint8_t *payload = NULL;
          uint8_t *pkt_syn_ack_send =
              create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                            ext_len, ext_data, payload, payload_len);

          sendto(sockfd, pkt_syn_ack_send, plen, 0,
                 (struct sockaddr *)&(sock->conn), conn_len);
          free(pkt_syn_ack_send);
          uint8_t *pkt_ack_recv = check_for_data(sock, TIMEOUT);

          cmu_tcp_header_t *hdr_two = (cmu_tcp_header_t *)pkt_ack_recv;
          int acked = (get_ack(hdr_two) == seq);

          free(pkt_ack_recv);

          if (acked) {
            break;
          }
        }
      }
      break;

    default:
      perror("Unknown Flag");
      return EXIT_ERROR;
  }
  getsockname(sockfd, (struct sockaddr *)&my_addr, &len);
  sock->my_port = ntohs(my_addr.sin_port);
  // on opening the socket the backend begins
  pthread_create(&(sock->thread_id), NULL, begin_backend, (void *)sock);
  return EXIT_SUCCESS;
}

int cmu_close(cmu_socket_t *sock) {
  while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
  }
  sock->dying = 1;
  pthread_mutex_unlock(&(sock->death_lock));

  pthread_join(sock->thread_id, NULL);

  if (sock != NULL) {
    if (sock->received_buf != NULL) {
      free(sock->received_buf);
    }
    if (sock->sending_buf != NULL) {
      free(sock->sending_buf);
    }
  } else {
    perror("ERROR null socket\n");
    return EXIT_ERROR;
  }
  return close(sock->socket);
}

int cmu_read(cmu_socket_t *sock, void *buf, int length, cmu_read_mode_t flags) {
  uint8_t *new_buf;
  int read_len = 0;

  if (length < 0) {
    perror("ERROR negative length");
    return EXIT_ERROR;
  }
  // locking recv_lock, returns non-zero on error
  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }

  switch (flags) {
    case NO_FLAG:
      while (sock->received_len == 0) {
        // idea is that when the client/server goes to read they set the NO_FLAg
        // this sets the wait-cond
        //
        // this should resume once pthread_cond_signal(&(sock->wait_cond)) is
        // called in the other method (as in hey! there's something received...)
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock));
      }
    // Fall through.
    case NO_WAIT:
      if (sock->received_len > 0) {
        if (sock->received_len > length)
          read_len = length;
        else
          read_len = sock->received_len;

        memcpy(buf, sock->received_buf, read_len);
        if (read_len < sock->received_len) {
          new_buf = malloc(sock->received_len - read_len);
          memcpy(new_buf, sock->received_buf + read_len,
                 sock->received_len - read_len);
          free(sock->received_buf);
          sock->received_len -= read_len;
          sock->received_buf = new_buf;
        } else {
          free(sock->received_buf);
          sock->received_buf = NULL;
          sock->received_len = 0;
        }
      }
      break;
    default:
      perror("ERROR Unknown flag.\n");
      read_len = EXIT_ERROR;
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  return read_len;
}

int cmu_write(cmu_socket_t *sock, const void *buf, int length) {
  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }
  if (sock->sending_buf == NULL)
    sock->sending_buf = malloc(length);
  else
    sock->sending_buf = realloc(sock->sending_buf, length + sock->sending_len);
  memcpy(sock->sending_buf + sock->sending_len, buf, length);
  sock->sending_len += length;

  pthread_mutex_unlock(&(sock->send_lock));
  return EXIT_SUCCESS;
}
