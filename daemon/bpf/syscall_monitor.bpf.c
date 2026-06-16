// BPF program: reports security-relevant system calls to user space via a ring
// buffer. Attached to the raw_syscalls/sys_enter tracepoint so a single program
// covers every syscall; we filter by number in-kernel and emit only the few of
// interest. Syscall numbers below are x86-64 (the build target).

#include "syscall_event.h"

// clang-format off
// Include order matters: linux/types.h provides __u32/__u64 used by the libbpf
// helper declarations, so it must precede bpf/bpf_helpers.h.
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
// clang-format on

char LICENSE[] SEC("license") = "GPL";

#define PROT_EXEC 0x4

#define SYS_clone 56
#define SYS_fork 57
#define SYS_vfork 58
#define SYS_execve 59
#define SYS_ptrace 101
#define SYS_mmap 9
#define SYS_execveat 322

// Minimal view of the raw_syscalls/sys_enter tracepoint context: an 8-byte
// common header, the syscall number, then the six syscall arguments.
struct sys_enter_ctx {
    unsigned long long _common;
    long id;
    unsigned long args[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} events SEC(".maps");

SEC("tp/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_ctx* ctx) {
    long id = ctx->id;
    unsigned int kind = 0;
    const void* exec_path = 0;

    if (id == SYS_execve) {
        kind = AV_SC_EXEC;
        exec_path = (const void*) ctx->args[0];
    } else if (id == SYS_execveat) {
        kind = AV_SC_EXEC;
        exec_path = (const void*) ctx->args[1];
    } else if (id == SYS_fork || id == SYS_vfork || id == SYS_clone) {
        kind = AV_SC_FORK;
    } else if (id == SYS_ptrace) {
        kind = AV_SC_PTRACE;
    } else if (id == SYS_mmap) {
        if (!(ctx->args[2] & PROT_EXEC)) {
            return 0;
        }
        kind = AV_SC_MMAP_EXEC;
    } else {
        return 0;
    }

    struct av_syscall_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    e->kind = kind;
    e->pid = (int) (pid_tgid & 0xffffffff);
    e->tgid = (int) (pid_tgid >> 32);
    e->arg = 0;
    e->filename[0] = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (kind == AV_SC_EXEC) {
        bpf_probe_read_user_str(&e->filename, sizeof(e->filename), exec_path);
    } else if (kind == AV_SC_PTRACE) {
        e->arg = ctx->args[0]; // ptrace request
    } else if (kind == AV_SC_MMAP_EXEC) {
        e->arg = ctx->args[2]; // protection flags
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
