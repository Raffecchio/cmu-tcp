#ifndef __RECV_H
#define __RECV_H

#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"


int is_valid_recv(cmu_socket_t *sock, const cmu_tcp_header_t* pkt);
int on_recv_pkt(cmu_socket_t *sock, const cmu_tcp_header_t *pkt);
uint8_t* chk_recv_pkt(cmu_socket_t *sock, cmu_read_mode_t flags);


#endif
