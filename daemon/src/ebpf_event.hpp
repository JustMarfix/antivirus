#pragma once

#include <cstdint>
#include <string>

/// @file ebpf_event.hpp
/// @brief Userspace representation of a system-call event from the BPF monitor.
///
/// This header is independent of libbpf so the formatting logic can be unit
/// tested without loading any BPF program (which requires privileges).

namespace av::daemon {

/// @brief Category of a security-relevant system call.
enum class SyscallKind {
    Exec,     ///< execve / execveat.
    Fork,     ///< fork / vfork / clone.
    Ptrace,   ///< ptrace.
    MmapExec, ///< mmap requesting executable memory (PROT_EXEC).
    Unknown   ///< Unrecognised kind value.
};

/// @brief A system call observed by the eBPF monitor.
struct SyscallEvent {
    SyscallKind kind = SyscallKind::Unknown; ///< What happened.
    std::int32_t pid = 0;                    ///< Thread id.
    std::int32_t tgid = 0;                   ///< Process id.
    std::uint64_t arg = 0;                   ///< ptrace request / mmap protection flags.
    std::string comm;                        ///< Short process name.
    std::string filename;                    ///< Target path for exec events.
};

/// @brief Map a raw kind value (from @c enum av_syscall_kind) to @ref SyscallKind.
/// @param raw_kind Numeric kind from the BPF event.
/// @return The corresponding enumerator, or SyscallKind::Unknown.
SyscallKind syscall_kind_from_raw(unsigned int raw_kind);

/// @brief Human-readable one-line description of an event.
/// @param event Event to describe.
/// @return A formatted string such as "exec pid=42 /bin/ls".
std::string describe_syscall_event(const SyscallEvent& event);

}
