/*
 * Copyright (c) 2008-2013, Dave Benson.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __PROTOBUF_C_RPC_RPC_DISPATCH_H_
#define __PROTOBUF_C_RPC_RPC_DISPATCH_H_

typedef struct _ProtobufCRPCDispatch ProtobufCRPCDispatch;
typedef struct _ProtobufCRPCDispatchTimer ProtobufCRPCDispatchTimer;
typedef struct _ProtobufCRPCDispatchIdle ProtobufCRPCDispatchIdle;

#include <protobuf-c/protobuf-c.h>

typedef enum
{
  PROTOBUF_C_RPC_EVENT_READABLE = (1<<0),
  PROTOBUF_C_RPC_EVENT_WRITABLE = (1<<1)
} ProtobufC_RPC_Events;

#ifdef WIN32
typedef SOCKET ProtobufC_RPC_FD;
#else
typedef int ProtobufC_RPC_FD;
#endif

/* Create or destroy a Dispatch */
ProtobufCRPCDispatch  *protobuf_c_rpc_dispatch_new (ProtobufCAllocator *allocator);
void                protobuf_c_rpc_dispatch_free(ProtobufCRPCDispatch *dispatch);

ProtobufCRPCDispatch  *protobuf_c_rpc_dispatch_default (void);
ProtobufCRPCDispatch  *protobuf_c_rpc_dispatch_default_new (void);

ProtobufCAllocator *protobuf_c_rpc_dispatch_peek_allocator (ProtobufCRPCDispatch *);

typedef void (*ProtobufCRPCDispatchCallback)  (ProtobufC_RPC_FD   fd,
                                            unsigned       events,
                                            void          *callback_data);

/* Registering file-descriptors to watch. */
void  protobuf_c_rpc_dispatch_watch_fd (ProtobufCRPCDispatch *dispatch,
                                    ProtobufC_RPC_FD        fd,
                                    unsigned            events,
                                    ProtobufCRPCDispatchCallback callback,
                                    void               *callback_data);
void  protobuf_c_rpc_dispatch_close_fd (ProtobufCRPCDispatch *dispatch,
                                    ProtobufC_RPC_FD        fd);
void  protobuf_c_rpc_dispatch_fd_closed(ProtobufCRPCDispatch *dispatch,
                                    ProtobufC_RPC_FD        fd);

/* Timers */
typedef void (*ProtobufCRPCDispatchTimerFunc) (ProtobufCRPCDispatch *dispatch,
                                            void              *func_data);
ProtobufCRPCDispatchTimer *
      protobuf_c_rpc_dispatch_add_timer(ProtobufCRPCDispatch *dispatch,
                                    unsigned           timeout_secs,
                                    unsigned           timeout_usecs,
                                    ProtobufCRPCDispatchTimerFunc func,
                                    void               *func_data);
ProtobufCRPCDispatchTimer *
      protobuf_c_rpc_dispatch_add_timer_millis
                                   (ProtobufCRPCDispatch *dispatch,
                                    unsigned           milliseconds,
                                    ProtobufCRPCDispatchTimerFunc func,
                                    void               *func_data);
void  protobuf_c_rpc_dispatch_remove_timer (ProtobufCRPCDispatchTimer *);

/* Idle functions */
typedef void (*ProtobufCRPCDispatchIdleFunc)   (ProtobufCRPCDispatch *dispatch,
                                             void               *func_data);
ProtobufCRPCDispatchIdle *
      protobuf_c_rpc_dispatch_add_idle (ProtobufCRPCDispatch *dispatch,
                                    ProtobufCRPCDispatchIdleFunc func,
                                    void               *func_data);
void  protobuf_c_rpc_dispatch_remove_idle (ProtobufCRPCDispatchIdle *);

/* --- API for use in standalone application --- */
/* Where you are happy just to run poll(2). */

/* protobuf_c_rpc_dispatch_run() 
 * Run one main-loop iteration, using poll(2) (or some system-level event system);
 * 'timeout' is in milliseconds, -1 for no timeout.
 */
void  protobuf_c_rpc_dispatch_run      (ProtobufCRPCDispatch *dispatch);


/* --- API for those who want to embed a dispatch into their own main-loop --- */
typedef struct {
  ProtobufC_RPC_FD fd;
  ProtobufC_RPC_Events events;
} ProtobufC_RPC_FDNotify;

typedef struct {
  ProtobufC_RPC_FD fd;
  ProtobufC_RPC_Events old_events;
  ProtobufC_RPC_Events events;
} ProtobufC_RPC_FDNotifyChange;

void  protobuf_c_rpc_dispatch_dispatch (ProtobufCRPCDispatch *dispatch,
                                    size_t              n_notifies,
                                    ProtobufC_RPC_FDNotify *notifies);
void  protobuf_c_rpc_dispatch_clear_changes (ProtobufCRPCDispatch *);


struct _ProtobufCRPCDispatch
{
  /* changes to the events you are interested in. */
  /* (this handles closed file-descriptors 
     in a manner agreeable to epoll(2) and kqueue(2)) */
  size_t n_changes;
  ProtobufC_RPC_FDNotifyChange *changes;

  /* the complete set of events you are interested in. */
  size_t n_notifies_desired;
  ProtobufC_RPC_FDNotify *notifies_desired;

  /* number of milliseconds to wait if no events occur */
  protobuf_c_boolean has_timeout;
  unsigned long timeout_secs;
  unsigned timeout_usecs;

  /* true if there is an idle function, in which case polling with
     timeout 0 is appropriate */
  protobuf_c_boolean has_idle;

  unsigned long last_dispatch_secs;
  unsigned last_dispatch_usecs;

  /* private data follows (see RealDispatch structure in .c file) */
};

void protobuf_c_rpc_dispatch_destroy_default (void);

#endif
