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
#include "recv.h"
#include "send.h"

#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))


int is_valid_recv(cmu_socket_t *sock, const cmu_tcp_header_t* pkt) {
  // TODO (?)
  (void)pkt;
  // if(get_flags(pkt) < 3 || get_flags(pkt) > 5)
  //   return 0;
  // if(get_dst(pkt) != 15441)
  //   return 0;
  // if(get_hlen(pkt) != sizeof(cmu_tcp_header_t))
  //   return 0;
  uint32_t payload_len = get_payload_len(pkt);
  if(payload_len > 0) {
    uint32_t seq_num = get_seq(pkt);
    if(seq_num < sock->window.next_seq_expected)
      return 0;
    /* ensure data would not require more space than the buffer size allows */
    /* while the window size can change, if the data does not contain any bytes
     * already ACKed, the window size is guaranteed to be at least as large as
     * what was advertised when the data was sent */
    if((seq_num + payload_len - sock->window.next_seq_expected)
        > buf_len(&(sock->window.recv_win)))
      return 0;
  }
  return 1;
}


static int on_recv_ack(cmu_socket_t* sock, const cmu_tcp_header_t *pkt) {
  uint32_t ack_num = get_ack(pkt);
  uint32_t adv_win = get_advertised_window(pkt);

  /* validate */
  int ack_valid = (ack_num <=
    sock->window.last_ack_received + buf_len(&(sock->window.send_win)));
  CHK_MSG("Error: Invalid ack number in received ACK packet", ack_valid);
  if(ack_num < sock->window.last_ack_received)
    return 0;

  int is_standalone = (get_payload_len(pkt) == 0);
  sock->window.dup_ack_cnt += (ack_num == sock->window.last_ack_received)
    && is_standalone;
  if(ack_num > sock->window.last_ack_received) {
    sock->window.last_send = get_time_ms();
    sock->window.dup_ack_cnt = 0;
    // sock->window.last_send should be updated only when passes the num_inflight,
    // in which case the code in send will do just that
  }
  uint32_t num_newly_acked = ack_num - sock->window.last_ack_received;
  sock->window.last_ack_received = ack_num;

  /* shift the sending window */
  buf_pop(&(sock->window.send_win), NULL, num_newly_acked);
  /* NOTE: num_newly_acked could be greater than num_inflight due to loss
   * retransmission */
  sock->window.num_inflight = num_newly_acked > sock->window.num_inflight ? 
    0 : sock->window.num_inflight - num_newly_acked;
  
  sock->window.adv_win = adv_win;
  sock->window.num_inflight = MIN(sock->window.num_inflight, adv_win);

  return 0;
}


static void update_recv_win(cmu_socket_t *sock) {
  /* resize the recv window as necesssary so it and the received buffer
   * do not store more than MAX_NETWORK_BUFFER bytes combined */
  uint32_t old_winlen = buf_len(&(sock->window.recv_win));
  while(pthread_mutex_lock(&(sock->recv_lock)) != 0) {}
  uint32_t recv_buf_len = buf_len(&(sock->received_buf));
  pthread_mutex_unlock(&(sock->recv_lock));
  uint32_t new_winlen = MAX_NETWORK_BUFFER - recv_buf_len;
  buf_ensure_len(&(sock->window.recv_win), new_winlen);
  buf_ensure_len(&(sock->window.recv_mask), new_winlen);
  /* zero out any newly made space in the mask at the end */
  for(uint32_t i = old_winlen; i < new_winlen; i++)
    buf_set(&(sock->window.recv_mask), i, 0);
}


/**
 * @return -1 if error, 0 otherwise
 */
static int on_recv_data(cmu_socket_t* sock, uint16_t dst, uint32_t seq_num,
    const uint8_t *payload, uint16_t payload_len) {
  (void) dst;
  /* ignore data if it has any bytes already ACKed */
  if(seq_num < sock->window.next_seq_expected)
    return 0;
  // printf("received packet with seq num %d and size %d\n", seq_num, payload_len);

  uint32_t last_seqnum = seq_num + payload_len;
  CHK_MSG("Error: Received data which would exceed the network buffer",
      last_seqnum - sock->window.next_seq_expected
      <= buf_len(&(sock->window.recv_win)))

  // CHK(buf_get(&(sock->window.recv_mask), 0) == 0);

  /* check if data can be popped & added to the received buffer */
  int data_made_available_to_user = (seq_num == sock->window.next_seq_expected);
  if(data_made_available_to_user) {
    /* get as much data as possible from the window, based on the recv mask */
    uint32_t pop_len = payload_len;
    uint32_t winlen = buf_len(&(sock->window.recv_win));
    while((pop_len < winlen)
        && (buf_get(&(sock->window.recv_mask), pop_len) > 0))
      ++pop_len;
    uint8_t *pop_data = NULL;
    CHK(buf_pop(&(sock->window.recv_win), &pop_data, pop_len) == pop_len);
    CHK(buf_pop(&(sock->window.recv_mask), NULL, pop_len) == pop_len);
    memcpy(pop_data, payload, payload_len);
    sock->window.next_seq_expected += pop_len;
    while(pthread_mutex_lock(&(sock->recv_lock)) != 0) {}
    buf_append(&(sock->received_buf), pop_data, pop_len);
    pthread_mutex_unlock(&(sock->recv_lock));
  }

  update_recv_win(sock);

  if(!data_made_available_to_user) {
    /* mark the recv buffer & recv mask */
    uint32_t buf_start = seq_num - sock->window.next_seq_expected;
    buf_ensure_len(&(sock->window.recv_win), payload_len);
    for(uint32_t i = 0; i < payload_len; i++) {
      buf_set(&(sock->window.recv_mask), buf_start + i, 1);
      buf_set(&(sock->window.recv_win), buf_start + i, payload[i]);
    }
  }

  /* reminder: sock->window.last_seq_received is useful when waiting to die */
  sock->window.last_seq_received = MAX(sock->window.last_seq_received,
      last_seqnum - 1);

  if(data_made_available_to_user)
    pthread_cond_signal(&(sock->wait_cond));

  return payload_len;
}


/**
 * Returns the amount of bytes of new data which was received which can fit in the window
 */
int on_recv_pkt(cmu_socket_t *sock, const cmu_tcp_header_t *pkt) {
  uint8_t flags = get_flags(pkt);
  uint16_t payload_len = get_payload_len(pkt);
  if(flags & ACK_FLAG_MASK) {
    on_recv_ack(sock, pkt);
  }
  
  // if(payload_len > 0) {
  if(1) {
    uint32_t num_recv = on_recv_data(sock, get_dst(pkt), get_seq(pkt),
        get_payload((uint8_t*)pkt), payload_len);
    CHK(num_recv)
    return payload_len;
  }
  
  return 0;
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

