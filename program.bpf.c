// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 trace-network-Authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct event {
  gadget_timestamp timestamp;
  gadget_mntns_id mntns_id;
  pid_t pid;
  char comm[TASK_COMM_LEN];
  gadget_syscall syscall_raw;
  struct gadget_l4endpoint_t address;
  int fd;
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(network_tracer, events, event);

static __always_inline int
handle_network_event(struct trace_event_raw_sys_enter *ctx) {
  struct event *event;
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u64 mntns_id;

  mntns_id = gadget_get_mntns_id();

  if (gadget_should_discard_mntns_id(mntns_id))
    return 0;

  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  struct sockaddr *addr = (struct sockaddr *)ctx->args[1];

  struct sockaddr_in *addrv4 = (struct sockaddr_in *)addr;
  bpf_probe_read(&event->address.addr_raw.v4,
                 sizeof(event->address.addr_raw.v4), &addrv4->sin_addr.s_addr);
  bpf_probe_read(&event->address.port, sizeof(event->address.port),
                 &addrv4->sin_port);
  event->fd = (int)ctx->args[0];
  event->address.port = bpf_ntohs(event->address.port);
  event->address.version = 4;
  event->mntns_id = mntns_id;
  event->timestamp = bpf_ktime_get_boot_ns();
  event->mntns_id = gadget_get_mntns_id();
  event->pid = pid_tgid >> 32;
  event->syscall_raw = ctx->id;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  /* emit event */
  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__sys_enter_enter(struct trace_event_raw_sys_enter *ctx) {
  return handle_network_event(ctx);
}

SEC("tracepoint/syscalls/sys_enter_accept")
int tracepoint__sys_enter_accept(struct trace_event_raw_sys_enter *ctx) {
  return handle_network_event(ctx);
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int tracepoint__sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
  return handle_network_event(ctx);
}

char LICENSE[] SEC("license") = "GPL";
