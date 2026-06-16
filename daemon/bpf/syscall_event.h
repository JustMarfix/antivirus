#ifndef AV_SYSCALL_EVENT_H
#define AV_SYSCALL_EVENT_H

/* Shared layout for events passed from the BPF program to user space.
 * Included by both the BPF C program and the C++ loader, so it must stay plain C
 * with a fixed, matching memory layout. */

#define AV_COMM_LEN 16
#define AV_FILENAME_LEN 256

/* Kind of security-relevant system call observed. */
enum av_syscall_kind {
    AV_SC_EXEC = 1,      /* execve / execveat */
    AV_SC_FORK = 2,      /* fork / vfork / clone */
    AV_SC_PTRACE = 3,    /* ptrace */
    AV_SC_MMAP_EXEC = 4, /* mmap with PROT_EXEC */
};

/* One observed system call. */
struct av_syscall_event {
    unsigned int kind;              /* enum av_syscall_kind */
    int pid;                        /* thread id (kernel pid) */
    int tgid;                       /* process id (kernel tgid) */
    unsigned long long arg;         /* ptrace request / mmap prot, when relevant */
    char comm[AV_COMM_LEN];         /* short process name */
    char filename[AV_FILENAME_LEN]; /* target path for exec events */
};

#endif /* AV_SYSCALL_EVENT_H */
