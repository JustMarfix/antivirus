#include "ebpf_event.hpp"

#include "syscall_event.h"

namespace av::daemon {

SyscallKind syscall_kind_from_raw(unsigned int raw_kind) {
    switch (raw_kind) {
    case AV_SC_EXEC:
        return SyscallKind::Exec;
    case AV_SC_FORK:
        return SyscallKind::Fork;
    case AV_SC_PTRACE:
        return SyscallKind::Ptrace;
    case AV_SC_MMAP_EXEC:
        return SyscallKind::MmapExec;
    default:
        return SyscallKind::Unknown;
    }
}

std::string describe_syscall_event(const SyscallEvent& event) {
    std::string base = event.comm + "[" + std::to_string(event.tgid) + "] ";
    switch (event.kind) {
    case SyscallKind::Exec:
        return base + "exec " + event.filename;
    case SyscallKind::Fork:
        return base + "fork";
    case SyscallKind::Ptrace:
        return base + "ptrace request=" + std::to_string(event.arg);
    case SyscallKind::MmapExec:
        return base + "mmap PROT_EXEC prot=" + std::to_string(event.arg);
    case SyscallKind::Unknown:
        return base + "unknown syscall";
    }
    return base + "unknown syscall";
}

}
