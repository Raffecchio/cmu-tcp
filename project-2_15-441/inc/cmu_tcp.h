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
 * This file defines the API for the CMU TCP implementation.
 */

#ifndef PROJECT_2_15_441_INC_CMU_TCP_H_
#define PROJECT_2_15_441_INC_CMU_TCP_H_

#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "cmu_packet.h"
#include "grading.h"

#include <sys/time.h>
#include "buffer.h"


#define EXIT_SUCCESS 0
#define EXIT_ERROR -1
#define EXIT_FAILURE 1


/**
 * Information necessary for windowing in both sending and receiving.
 *
 * A window here is defined as a contiguous portion at the start or end of
 * the containing socket's sending buffer or receiving buffer, respectively.
 * The size buffer!
 */
typedef struct {
  uint32_t last_ack_received;
  uint32_t num_inflight;  // current # of unacknowledged bytes sent
  uint32_t adv_win;  // max # of bytes in the window
  buf_t send_win;
  time_t last_send;  // last send time for leftmost window byte in seconds
  uint32_t dup_ack_cnt;  // duplicate ACK count (only standalone ACKS should
                         // add to this)

  uint32_t next_seq_expected;
  uint32_t last_seq_received;
  buf_t recv_win;  // a buffer temporarily holding received data
  buf_t recv_mask;  // a mask to keep track of which bytes in the
                        // receive window were received
  // uint32_t recv_win_cap;  // current max window size (depends on received_buf)
  uint32_t cwin;
} window_t;

// int init_window(window_t *window);

/**
 * CMU-TCP socket types. (DO NOT CHANGE.)
 */
typedef enum {
  TCP_INITIATOR = 0,
  TCP_LISTENER = 1,
} cmu_socket_type_t;

/**
 * This structure holds the state of a socket. You may modify this structure as
 * you see fit to include any additional state you need for your implementation.
 */
typedef struct {
  cmu_socket_type_t type;
  int dying;

  /* sending data */
  buf_t sending_buf;

  /* receiving data */
  buf_t received_buf;

  /* windowing info */
  window_t window;

  /* concurrency */
  pthread_mutex_t send_lock;
  pthread_mutex_t recv_lock;
  pthread_mutex_t death_lock;
  pthread_cond_t wait_cond;

  /* underlying network info */
  int socket;
  pthread_t thread_id;
  uint16_t my_port;
  struct sockaddr_in conn;
  uint32_t ssthresh;
  int is_fast_recovery;
} cmu_socket_t;

/*
 * DO NOT CHANGE THE DECLARATIONS BELOW
 */

/**
 * Read mode flags supported by a CMU-TCP socket.
 */
typedef enum {
  NO_FLAG = 0,  // Default behavior: block indefinitely until data is available.
  NO_WAIT,      // Return immediately if no data is available.
  TIMEOUT,      // Block until data is available or the timeout is reached.
} cmu_read_mode_t;

/**
 * Constructs a CMU-TCP socket.
 *
 * An Initiator socket is used to connect to a Listener socket.
 *
 * @param sock The structure with the socket state. It will be initialized by
 *             this function.
 * @param socket_type Indicates the type of socket: Listener or Initiator.
 * @param port Port to either connect to, or bind to. (Based on socket_type.)
 * @param server_ip IP address of the server to connect to. (Only used if the
 *                 socket is an initiator.)
 *
 * @return 0 on success, -1 on error.
 */
int cmu_socket(cmu_socket_t* sock, const cmu_socket_type_t socket_type,
               const int port, const char* server_ip);

/**
 * Closes a CMU-TCP socket.
 *
 * @param sock The socket to close.
 *
 * @return 0 on success, -1 on error.
 */
int cmu_close(cmu_socket_t* sock);

/**
 * Reads data from a CMU-TCP socket.
 *
 * If there is data available in the socket buffer, it is placed in the
 * destination buffer.
 *
 * @param sock The socket to read from.
 * @param buf The buffer to read into.
 * @param length The maximum number of bytes to read.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information. `TIMEOUT` is not
 *             implemented for CMU-TCP.
 *
 * @return The number of bytes read on success, -1 on error.
 */
int cmu_read(cmu_socket_t* sock, void* buf, const int length,
             cmu_read_mode_t flags);

/**
 * Writes data to a CMU-TCP socket.
 *
 * @param sock The socket to write to.
 * @param buf The data to write.
 * @param length The number of bytes to write.
 *
 * @return 0 on success, -1 on error.
 */
int cmu_write(cmu_socket_t* sock, const void* buf, int length);

/*
 * You can declare more functions after this point if you need to.
 */
int init_sock(cmu_socket_t *sock, const cmu_socket_type_t socket_type,
    const int port, const char *server_ip);

#endif  // PROJECT_2_15_441_INC_CMU_TCP_H_
