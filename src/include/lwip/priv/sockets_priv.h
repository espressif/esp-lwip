/**
 * @file
 * Sockets API internal implementations (do not use in application code)
 */

/*
 * Copyright (c) 2017 Joel Cunningham, Garmin International, Inc. <joel.cunningham@garmin.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Joel Cunningham <joel.cunningham@me.com>
 *
 */
#ifndef LWIP_HDR_SOCKETS_PRIV_H
#define LWIP_HDR_SOCKETS_PRIV_H

#include "lwip/opt.h"

#if LWIP_SOCKET /* don't build if not configured for use in lwipopts.h */

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SELWAIT_T
#define SELWAIT_T u8_t
#endif

#define NUM_SOCKETS MEMP_NUM_NETCONN

/** Contains all internal pointers and states used for a socket */
struct lwip_sock {
  /** sockets currently are built on netconns, each socket has one netconn */
  struct netconn *conn;
  /** data that was left from the previous read */
  void *lastdata;
  /** offset in the data that was left from the previous read */
  u16_t lastoffset;
  /** number of times data was received, set by event_callback(),
      tested by the receive and select functions */
  s16_t rcvevent;
  /** number of times data was ACKed (free send buffer), set by event_callback(),
      tested by select */
  u16_t sendevent;
  /** error happened for this socket, set by event_callback(), tested by select */
  u16_t errevent;
  /** last error that occurred on this socket (in fact, all our errnos fit into an u8_t) */
  u8_t err;

#if ESP_THREAD_SAFE
  /* lock is used to protect state/ref field, however this lock is not a perfect lock, e.g
   * taskA and taskB can access sock X, then taskA freed sock X, before taskB detect
   * this, taskC reuse sock X, then when taskB try to access sock X, problem may happen.
   * A mitigation solution may be, when allocate a socket, alloc the least frequently used
   * socket.
   */
  sys_mutex_t lock;

  /* can be LWIP_SOCK_OPEN/LWIP_SOCK_CLOSING/LWIP_SOCK_CLOSED */
  u8_t state;

  /* if ref is 0, the sock need/can to be freed */
  s8_t ref;

  /* indicate how long the sock is in LWIP_SOCK_CLOSED status */
  u8_t age;
#endif

  /** counter of how many threads are waiting for this socket using select */
  SELWAIT_T select_waiting;
};

#ifdef __cplusplus
}
#endif

#endif /* LWIP_SOCKET */

#endif /* LWIP_HDR_SOCKETS_PRIV_H */
