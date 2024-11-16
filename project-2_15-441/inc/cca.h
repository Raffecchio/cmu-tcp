#ifndef __cca_H
#define __cca_H


#include <poll.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"


void cca_dup_ack_cnt_three(cmu_socket_t *sock);
void cca_dup_ack_lt_three(cmu_socket_t *sock);
void cca_new_ack(cmu_socket_t *sock);
void fast_recovery(cmu_socket_t *sock);
void cca_enter_ss_from_timeout(cmu_socket_t *sock);
#endif