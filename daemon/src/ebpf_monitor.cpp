#include "ebpf_monitor.hpp"

#include "avcore/error.hpp"
#include "syscall_event.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>

extern "C" {
extern const unsigned char av_syscall_monitor_bpf[];
extern const unsigned int av_syscall_monitor_bpf_len;
}

namespace av::daemon {

namespace {

std::string& libbpf_log() {
    static std::string log;
    return log;
}

int capture_libbpf(enum libbpf_print_level level, const char* format, va_list args) {
    if (level > LIBBPF_WARN) {
        return 0;
    }
    char buffer[1024];
    int written = std::vsnprintf(buffer, sizeof(buffer), format, args);
    if (written > 0) {
        libbpf_log().append(buffer);
    }
    return 0;
}

std::string with_libbpf_log(const char* prefix) {
    std::string message = prefix;
    if (!libbpf_log().empty()) {
        message += ": ";
        message += libbpf_log();
    }
    return message;
}

}

EbpfMonitor::EbpfMonitor(Handler handler) : handler_(std::move(handler)) {
    libbpf_set_print(capture_libbpf);
    libbpf_log().clear();

    object_ = bpf_object__open_mem(av_syscall_monitor_bpf, av_syscall_monitor_bpf_len, nullptr);
    if (object_ == nullptr) {
        throw IoError(with_libbpf_log("eBPF: failed to open embedded program"));
    }

    if (bpf_object__load(object_) != 0) {
        std::string message =
            with_libbpf_log("eBPF: failed to load program (needs CAP_BPF/CAP_SYS_ADMIN and BTF)");
        bpf_object__close(object_);
        object_ = nullptr;
        throw IoError(message);
    }

    bpf_program* program = nullptr;
    bpf_object__for_each_program(program, object_) {
        bpf_link* link = bpf_program__attach(program);
        if (link == nullptr) {
            throw IoError(with_libbpf_log(
                (std::string("eBPF: failed to attach program: ") + std::strerror(errno)).c_str()));
        }
        links_.push_back(link);
    }

    int map_fd = bpf_object__find_map_fd_by_name(object_, "events");
    if (map_fd < 0) {
        throw IoError("eBPF: ring-buffer map 'events' not found");
    }

    ring_ = ring_buffer__new(map_fd, &EbpfMonitor::on_event, this, nullptr);
    if (ring_ == nullptr) {
        throw IoError("eBPF: failed to create ring buffer");
    }
}

EbpfMonitor::~EbpfMonitor() {
    if (ring_ != nullptr) {
        ring_buffer__free(ring_);
    }
    for (bpf_link* link : links_) {
        bpf_link__destroy(link);
    }
    if (object_ != nullptr) {
        bpf_object__close(object_);
    }
}

int EbpfMonitor::epoll_fd() const noexcept {
    return ring_buffer__epoll_fd(ring_);
}

void EbpfMonitor::process_available() {
    ring_buffer__consume(ring_);
}

int EbpfMonitor::on_event(void* ctx, void* data, std::size_t size) {
    auto* self = static_cast<EbpfMonitor*>(ctx);
    if (size < sizeof(av_syscall_event)) {
        return 0;
    }
    const auto* raw = static_cast<const av_syscall_event*>(data);

    SyscallEvent event;
    event.kind = syscall_kind_from_raw(raw->kind);
    event.pid = raw->pid;
    event.tgid = raw->tgid;
    event.arg = raw->arg;
    event.comm.assign(raw->comm, ::strnlen(raw->comm, AV_COMM_LEN));
    event.filename.assign(raw->filename, ::strnlen(raw->filename, AV_FILENAME_LEN));

    if (self->handler_) {
        self->handler_(event);
    }
    return 0;
}

}
