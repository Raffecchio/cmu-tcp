#ifndef __SEND_H
#define __SEND_H

#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"


int on_recv_pkt(cmu_socket_t *sock, const cmu_tcp_header_t *pkt);
cmu_tcp_header_t* chk_send_pkt(cmu_socket_t *sock);
cmu_tcp_header_t* get_base_pkt(cmu_socket_t *sock, uint16_t pl_len);
double get_time_ms(void);


#endif

