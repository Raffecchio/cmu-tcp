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
 * This file implements a simple CMU-TCP server. Its purpose is to provide
 * simple test cases and demonstrate how the sockets will be used.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "cmu_tcp.h"

#define BUF_SIZE 11000

/*
 * Param: sock - used for reading and writing to a connection
 *
 * Purpose: To provide some simple test cases and demonstrate how
 *  the sockets will be used.
 *
 */
void functionality(cmu_socket_t *sock) {
  uint8_t buf[BUF_SIZE];
  FILE *fp;
  int n;

  (void)fp;
  cmu_write(sock, "a", 1);

}

int main() {
  int portno;
  char *serverip;
  char *serverport;
  cmu_socket_t socket;
  
  serverip = getenv("server15441");
  if (!serverip) {
    serverip = "10.0.1.1";
  }

  serverport = getenv("serverport15441");
  if (!serverport) {
    serverport = "15441";
  }
  portno = (uint16_t)atoi(serverport);
  if (cmu_socket(&socket, TCP_LISTENER, portno, serverip) < 0) {
    exit(EXIT_FAILURE);
  }

  functionality(&socket);

  if (cmu_close(&socket) < 0) {
    exit(EXIT_FAILURE);
  }

  return EXIT_SUCCESS;
}
