#include "ebpf_event.hpp"

#include <doctest/doctest.h>

using namespace av::daemon;

TEST_CASE("syscall_kind_from_raw maps known and unknown values") {
    CHECK(syscall_kind_from_raw(1) == SyscallKind::Exec);
    CHECK(syscall_kind_from_raw(2) == SyscallKind::Fork);
    CHECK(syscall_kind_from_raw(3) == SyscallKind::Ptrace);
    CHECK(syscall_kind_from_raw(4) == SyscallKind::MmapExec);
    CHECK(syscall_kind_from_raw(99) == SyscallKind::Unknown);
}

TEST_CASE("describe_syscall_event renders each kind") {
    SyscallEvent exec;
    exec.kind = SyscallKind::Exec;
    exec.tgid = 1234;
    exec.comm = "bash";
    exec.filename = "/usr/bin/ls";
    CHECK(describe_syscall_event(exec) == "bash[1234] exec /usr/bin/ls");

    SyscallEvent fork;
    fork.kind = SyscallKind::Fork;
    fork.tgid = 10;
    fork.comm = "sh";
    CHECK(describe_syscall_event(fork) == "sh[10] fork");

    SyscallEvent ptrace;
    ptrace.kind = SyscallKind::Ptrace;
    ptrace.tgid = 7;
    ptrace.comm = "gdb";
    ptrace.arg = 16;
    CHECK(describe_syscall_event(ptrace) == "gdb[7] ptrace request=16");

    SyscallEvent mmap;
    mmap.kind = SyscallKind::MmapExec;
    mmap.tgid = 3;
    mmap.comm = "jit";
    mmap.arg = 7;
    CHECK(describe_syscall_event(mmap) == "jit[3] mmap PROT_EXEC prot=7");
}
