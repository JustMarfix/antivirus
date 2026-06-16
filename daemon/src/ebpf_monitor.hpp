#pragma once

#include "ebpf_event.hpp"

#include <functional>
#include <vector>

struct bpf_object;
struct bpf_link;
struct ring_buffer;

/// @file ebpf_monitor.hpp
/// @brief libbpf-based monitor of security-relevant system calls.

namespace av::daemon {

/// @brief Loads the embedded BPF program, attaches it and streams events.
///
/// The program reports @c execve, @c fork/@c vfork/@c clone, @c ptrace and
/// @c mmap-with-@c PROT_EXEC via a ring buffer. Loading requires privileges
/// (CAP_BPF/CAP_SYS_ADMIN) and a sufficiently recent kernel; otherwise the
/// constructor throws. The ring buffer's epoll descriptor (@ref epoll_fd) can be
/// driven by an external event loop.
class EbpfMonitor {
  public:
    /// @brief Callback invoked for each observed system call.
    using Handler = std::function<void(const SyscallEvent&)>;

    /// @brief Load, verify and attach the BPF program.
    /// @param handler Callback for decoded events.
    /// @throws av::IoError if the program cannot be loaded or attached.
    explicit EbpfMonitor(Handler handler);

    /// @brief Detach the program and release all BPF resources.
    ~EbpfMonitor();

    EbpfMonitor(const EbpfMonitor&) = delete;
    EbpfMonitor& operator=(const EbpfMonitor&) = delete;

    /// @brief Epoll descriptor signalling that ring-buffer data is available.
    /// @return A non-owning descriptor for use with an event loop.
    int epoll_fd() const noexcept;

    /// @brief Consume and dispatch all currently available events.
    void process_available();

  private:
    static int on_event(void* ctx, void* data, std::size_t size);

    Handler handler_;
    bpf_object* object_ = nullptr;
    ring_buffer* ring_ = nullptr;
    std::vector<bpf_link*> links_;
};

}
