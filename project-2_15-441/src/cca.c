
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

void cca_dup_ack(cmu_socket_t *sock) {
  if (sock->is_fast_recovery == 0) {
    
      int32_t cwin = sock->window.cwin;
      int32_t ssthresh = sock->ssthresh;
      int is_slow_start = cwin < ssthresh;
      ssthresh = is_slow_start ? (cwin * 2) : (cwin * .5);
      sock->window.cwin = ssthresh + (3 * MSS);
      sock->is_fast_recovery = 1;
      fast_retransmit(sock);
    
  } else {
      sock->window.cwin += MSS;
  }
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
  return;
}

void fast_retransmit(cmu_socket_t *sock) {
    
  sock->is_fast_recovery = 1;
  cmu_tcp_header_t *pkt_send = get_win_pkt(sock, 0);

  struct timeval now;
  gettimeofday(&now, NULL);
  sock->window.last_send = now.tv_sec;

  if (pkt_send != NULL) {
    set_ack(pkt_send, sock->window.next_seq_expected);
    set_flags(pkt_send, ACK_FLAG_MASK);
    send_pkt(sock, pkt_send);
  }
  
  uint8_t *fast_rec_ack_pkt = chk_recv_pkt(sock, TIMEOUT);
  if (fast_rec_ack_pkt == NULL) {
    cca_enter_ss_from_timeout(sock);
    return;
  }
  if ((fast_rec_ack_pkt != NULL) && is_valid_recv(sock, (cmu_tcp_header_t*) fast_rec_ack_pkt)) {
    on_recv_pkt(sock, (cmu_tcp_header_t*) fast_rec_ack_pkt);
  }
  return;
}

void cca_enter_ss_from_timeout(cmu_socket_t *sock) {
  sock->is_fast_recovery = 0;
  sock->ssthresh = sock->window.cwin / 2;
  sock->window.cwin = MSS;
  sock->window.dup_ack_cnt = 0;
  return;
}