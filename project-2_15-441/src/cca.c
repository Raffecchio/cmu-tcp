
#include "cca.h"

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "backend.h"
#include "cmu_packet.h"
#include "cmu_tcp.h"
#include "error.h"
#include "recv.h"
#include "send.h"


#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

void cca_dup_ack_3(cmu_socket_t *sock) {
  if (sock->is_fast_recovery == 0) {
      int32_t cwin = sock->window.cwin;
      sock->ssthresh = cwin * .5;
      sock->window.cwin = sock->ssthresh + (3 * MSS);
      sock->is_fast_recovery = 1;
      // fast_recovery(sock); 
  } else {
      sock->window.cwin += MSS;
  }
  sock->window.cwin = MAX(sock->window.cwin, MSS);
  sock->ssthresh = MAX(sock->ssthresh, MSS);
  return;
}

void cca_new_ack(cmu_socket_t *sock) {
  sock->window.dup_ack_cnt = 0;
  int is_slow_start = sock->window.cwin < sock->ssthresh;
  if (sock->is_fast_recovery == 1) {
    sock->window.cwin = sock->ssthresh;
    sock->is_fast_recovery = 0;
  } else if (is_slow_start == 1) {
    sock->window.cwin += MSS;
  } else {  // congestion avoidance
    sock->window.cwin += (MSS * (MSS / sock->window.cwin));
  }
  sock->window.cwin = MAX(sock->window.cwin, MSS);
  sock->window.cwin = MIN(sock->window.cwin, MAX_NETWORK_BUFFER);
  sock->ssthresh = MAX(sock->ssthresh, MSS);
  return;
}

void fast_recovery(cmu_socket_t *sock) {
  sock->is_fast_recovery = 1;
  cmu_tcp_header_t *pkt_send = get_win_pkt(sock, 0);
  // Note: 
  // num_inflight should not change since we are retransmitting something unacked/blocking the sending window
  // int new_inflight = MAX(get_payload_len(pkt_send), sock->window.num_inflight);
  struct timeval now;
  gettimeofday(&now, NULL);

  // Note: should always update the last_send
  sock->window.last_send = now.tv_sec;

  if (pkt_send != NULL) {
    set_ack(pkt_send, sock->window.next_seq_expected);
    set_flags(pkt_send, ACK_FLAG_MASK);
    send_pkt(sock, pkt_send);
  }
  
  uint8_t *fast_rec_ack_pkt = chk_recv_pkt(sock, TIMEOUT);
  // Confirm this is how to check for timeout?
  if (fast_rec_ack_pkt == NULL) {
    // cca_enter_ss_from_timeout(sock);
    // this will trigger timout logic in main loop
    return;
  }
  if ((fast_rec_ack_pkt != NULL) && is_valid_recv(sock, (const cmu_tcp_header_t *)fast_rec_ack_pkt)) {
    on_recv_pkt(sock, (const cmu_tcp_header_t *) fast_rec_ack_pkt);
  }
  return;
}

void cca_enter_ss_from_timeout(cmu_socket_t *sock) {
  sock->window.dup_ack_cnt = 0;
  sock->is_fast_recovery = 0;
  sock->ssthresh = sock->window.cwin / 2;
  sock->window.cwin = MSS;
  sock->ssthresh = MAX(sock->ssthresh, MSS);
  return;
}
