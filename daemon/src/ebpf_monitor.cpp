#include "ebpf_monitor.hpp"

#include "avcore/error.hpp"
#include "syscall_event.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstdarg>
#include <cstring>

// The BPF object code is embedded into the binary at build time (see
// daemon/CMakeLists.txt and cmake/EmbedFile.cmake).
extern "C" {
extern const unsigned char av_syscall_monitor_bpf[];
extern const unsigned int av_syscall_monitor_bpf_len;
}

namespace av::daemon {

namespace {

int silence_libbpf(enum libbpf_print_level, const char*, va_list) {
    return 0;
}

}

EbpfMonitor::EbpfMonitor(Handler handler) : handler_(std::move(handler)) {
    libbpf_set_print(silence_libbpf);

    object_ = bpf_object__open_mem(av_syscall_monitor_bpf, av_syscall_monitor_bpf_len, nullptr);
    if (object_ == nullptr) {
        throw IoError("eBPF: failed to open embedded program");
    }

    if (bpf_object__load(object_) != 0) {
        bpf_object__close(object_);
        object_ = nullptr;
        throw IoError("eBPF: failed to load program (needs CAP_BPF/CAP_SYS_ADMIN and BTF)");
    }

    bpf_program* program = nullptr;
    bpf_object__for_each_program(program, object_) {
        bpf_link* link = bpf_program__attach(program);
        if (link == nullptr) {
            throw IoError(std::string("eBPF: failed to attach program: ") + std::strerror(errno));
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
