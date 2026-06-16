#include "daemon.hpp"

#include "avcore/error.hpp"
#include "avcore/util/path.hpp"

#include <algorithm>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/post.hpp>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <grp.h>
#include <sys/stat.h>
#include <unistd.h>

namespace av::daemon {

namespace asio = boost::asio;

namespace {

std::int64_t now_ms() {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

// Grant the configured group/mode access to the listening socket so an
// unprivileged client can connect without being run as root (connecting to a
// Unix socket requires write permission on the socket file).
void apply_socket_permissions(const std::string& path, const std::string& group,
                              unsigned int mode) {
    unsigned int effective_mode = mode;
    if (!group.empty()) {
        struct group* grp = ::getgrnam(group.c_str());
        if (grp == nullptr) {
            throw IoError("unknown socket group: " + group);
        }
        if (::chown(path.c_str(), static_cast<uid_t>(-1), grp->gr_gid) != 0) {
            throw IoError(std::string("chown socket group failed: ") + std::strerror(errno));
        }
        if (effective_mode == 0) {
            effective_mode = 0660; // owner+group read/write by default
        }
    }
    if (effective_mode != 0) {
        if (::chmod(path.c_str(), static_cast<mode_t>(effective_mode)) != 0) {
            throw IoError(std::string("chmod socket failed: ") + std::strerror(errno));
        }
    }
}

}

AntivirusDaemon::AntivirusDaemon(asio::io_context& io, DaemonConfig config)
    : io_(io), config_(std::move(config)), own_pid_(::getpid()) {
    if (!config_.database_path.empty()) {
        database_.load_from_file(config_.database_path);
    }
    database_.build();

#ifdef AV_HAVE_YARA
    const scan::YaraScanner* yara_ptr = nullptr;
    if (!config_.yara_rules.empty()) {
        yara_scanner_.emplace();
        yara_scanner_->add_rules_path(config_.yara_rules);
        yara_scanner_->compile();
        yara_ptr = &*yara_scanner_;
    }
    scanner_.emplace(database_, 64 * 1024 * 1024, yara_ptr);
#else
    scanner_.emplace(database_);
#endif

    if (!config_.quarantine_dir.empty()) {
        quarantine_.emplace(config_.quarantine_dir);
        std::error_code ec;
        std::filesystem::path canonical =
            std::filesystem::weakly_canonical(quarantine_->store_dir(), ec);
        quarantine_prefix_ = (ec ? quarantine_->store_dir() : canonical).string();
    }

    std::string exclusions_path = config_.exclusions_path;
    if (exclusions_path.empty() && !config_.quarantine_dir.empty()) {
        exclusions_path =
            (std::filesystem::path(config_.quarantine_dir) / "exclusions.list").string();
    }
    exclusions_.emplace(exclusions_path);

    server_.emplace(io_, config_.socket_path,
                    [this](const ipc::Command& command) { return handle_command(command); });
    apply_socket_permissions(config_.socket_path, config_.socket_group, config_.socket_mode);

    if (config_.realtime && !config_.watch_path.empty()) {
        watcher_.emplace(config_.enforce);
        if (!quarantine_prefix_.empty()) {
            watcher_->set_excluded(quarantine_prefix_);
        }
        watcher_->watch_tree(config_.watch_path);
        // Duplicate the descriptors so ASIO owns copies purely for readiness
        // notification while the watcher keeps the originals for reads/responses.
        int fan_dup = ::dup(watcher_->fanotify_fd());
        int ino_dup = ::dup(watcher_->inotify_fd());
        if (fan_dup < 0 || ino_dup < 0) {
            throw IoError("failed to duplicate watcher descriptors");
        }
        fan_stream_.emplace(io_, fan_dup);
        ino_stream_.emplace(io_, ino_dup);
        wait_for_access();
        wait_for_structure();
    }

#ifdef AV_HAVE_EBPF
    if (config_.syscalls) {
        ebpf_.emplace([this](const SyscallEvent& event) { on_syscall(event); });
        int dup_fd = ::dup(ebpf_->epoll_fd());
        if (dup_fd < 0) {
            throw IoError("failed to duplicate eBPF epoll descriptor");
        }
        ebpf_stream_.emplace(io_, dup_fd);
        wait_for_syscalls();
    }
#endif
}

AntivirusDaemon::~AntivirusDaemon() {
    scan_cancel_.store(true);
    if (scan_thread_.joinable()) {
        scan_thread_.join();
    }
}

void AntivirusDaemon::wait_for_access() {
    fan_stream_->async_wait(asio::posix::stream_descriptor::wait_read,
                            [this](const boost::system::error_code& ec) {
                                if (ec) {
                                    return;
                                }
                                try {
                                    watcher_->process_access([this](const FileAccessEvent& event) {
                                        return on_access(event);
                                    });
                                } catch (const AvException&) {
                                    return;
                                }
                                wait_for_access();
                            });
}

void AntivirusDaemon::wait_for_structure() {
    ino_stream_->async_wait(asio::posix::stream_descriptor::wait_read,
                            [this](const boost::system::error_code& ec) {
                                if (ec) {
                                    return;
                                }
                                try {
                                    watcher_->process_structure();
                                } catch (const AvException&) {
                                    return;
                                }
                                wait_for_structure();
                            });
}

#ifdef AV_HAVE_EBPF
void AntivirusDaemon::wait_for_syscalls() {
    ebpf_stream_->async_wait(asio::posix::stream_descriptor::wait_read,
                             [this](const boost::system::error_code& ec) {
                                 if (ec) {
                                     return;
                                 }
                                 try {
                                     ebpf_->process_available();
                                 } catch (const AvException&) {
                                     return;
                                 }
                                 wait_for_syscalls();
                             });
}

void AntivirusDaemon::on_syscall(const SyscallEvent& event) {
    ipc::Event notice;
    notice.timestamp_ms = now_ms();
    notice.pid = event.tgid;
    notice.message = describe_syscall_event(event);
    switch (event.kind) {
    case SyscallKind::Exec:
        notice.kind = ipc::EventKind::FileExec;
        notice.path = event.filename;
        break;
    case SyscallKind::Fork:
        notice.kind = ipc::EventKind::ProcessStart;
        break;
    default:
        notice.kind = ipc::EventKind::Info;
        break;
    }

    if (event.kind == SyscallKind::Exec && !event.filename.empty() &&
        !util::is_subpath(event.filename, quarantine_prefix_) &&
        !(exclusions_ && exclusions_->is_excluded(event.filename))) {
        scan::ScanResult result = scanner_->scan_file(event.filename);
        ++scanned_count_;
        notice.verdict = scan::to_string(result.verdict);
        notice.threat_name = result.threat_name;
        if (result.infected()) {
            ++threat_count_;
            notice.kind = ipc::EventKind::ThreatDetected;
            if (quarantine_) {
                try {
                    quarantine::QuarantineEntry entry =
                        quarantine_->quarantine_file(event.filename, result.threat_name);
                    notice.message += "; quarantined as " + entry.id;
                } catch (const AvException& e) {
                    notice.message += std::string("; quarantine failed: ") + e.what();
                }
            }
        }
    }

    server_->broadcast(notice);
}
#endif

AccessDecision AntivirusDaemon::on_access(const FileAccessEvent& event) {
    if (event.pid == own_pid_ || paused_ || event.fd < 0) {
        return AccessDecision::Allow;
    }

    if (util::is_subpath(event.path, quarantine_prefix_)) {
        return AccessDecision::Allow;
    }

    if (exclusions_ && exclusions_->is_excluded(event.path)) {
        return AccessDecision::Allow;
    }

    scan::ScanResult result = scanner_->scan_fd(event.fd, event.path);
    ++scanned_count_;

    ipc::Event notice;
    notice.timestamp_ms = now_ms();
    notice.kind = event.is_exec ? ipc::EventKind::FileExec : ipc::EventKind::FileOpen;
    notice.path = event.path;
    notice.pid = event.pid;
    notice.verdict = scan::to_string(result.verdict);
    notice.threat_name = result.threat_name;

    bool can_block = event.needs_response; // true only in enforcing mode
    if (result.infected()) {
        ++threat_count_;
        notice.kind = ipc::EventKind::ThreatDetected;
        notice.message = can_block ? "access denied" : "threat detected";

        if (quarantine_ && !event.path.empty()) {
            try {
                quarantine::QuarantineEntry entry =
                    quarantine_->quarantine_file(event.path, result.threat_name);
                notice.message += "; quarantined as " + entry.id;
            } catch (const AvException& e) {
                notice.message += std::string("; quarantine failed: ") + e.what();
            }
        }
        server_->broadcast(notice);
        return can_block ? AccessDecision::Deny : AccessDecision::Allow;
    }

    server_->broadcast(notice);
    return AccessDecision::Allow;
}

ipc::Reply AntivirusDaemon::handle_command(const ipc::Command& command) {
    switch (command.kind) {
    case ipc::CommandKind::Ping:
        return ipc::Reply{true, "pong", "", "", {}};

    case ipc::CommandKind::ScanPath: {
        std::error_code ec;
        if (!std::filesystem::exists(command.path, ec)) {
            return ipc::Reply{false, "path does not exist: " + command.path, "error", "", {}};
        }

        if (std::filesystem::is_directory(command.path, ec)) {
            if (scan_active_.load()) {
                return ipc::Reply{false, "a scan is already in progress", "error", "", {}};
            }
            if (scan_thread_.joinable()) {
                scan_thread_.join();
            }
            std::vector<std::string> snapshot =
                exclusions_ ? exclusions_->list() : std::vector<std::string>{};
            scan_cancel_.store(false);
            scan_active_.store(true);
            scan_thread_ =
                std::thread([this, root = command.path, snapshot = std::move(snapshot)]() mutable {
                    run_directory_scan(std::move(root), std::move(snapshot));
                });
            return ipc::Reply{true, "scan started", "scanning", "", {}};
        }

        scan::ScanResult result = scanner_->scan_file(command.path);
        ++scanned_count_;
        if (result.infected()) {
            ++threat_count_;
            ipc::Event notice;
            notice.timestamp_ms = now_ms();
            notice.kind = ipc::EventKind::ThreatDetected;
            notice.path = command.path;
            notice.verdict = "infected";
            notice.threat_name = result.threat_name;
            notice.message = "on-demand scan";
            server_->broadcast(notice);
        }
        std::string detail;
        if (result.verdict == scan::Verdict::Error) {
            detail = "could not read file";
        } else if (result.infected()) {
            detail = "threat found — " + result.threat_name;
        } else {
            detail = "no threats found";
        }
        return ipc::Reply{result.verdict != scan::Verdict::Error,
                          detail,
                          scan::to_string(result.verdict),
                          result.threat_name,
                          {}};
    }

    case ipc::CommandKind::ScanCancel:
        if (!scan_active_.load()) {
            return ipc::Reply{true, "no scan in progress", "", "", {}};
        }
        scan_cancel_.store(true);
        return ipc::Reply{true, "cancelling scan", "", "", {}};

    case ipc::CommandKind::DeletePath: {
        // Permanently remove a flagged file straight from disk (used by the
        // "Scan results" view as an alternative to quarantine). Entries living
        // inside the quarantine store have their own delete command and must not
        // be removed through this path, otherwise the .meta/.quar pair desyncs.
        if (command.path.empty()) {
            return ipc::Reply{false, "delete path is empty", "error", "", {}};
        }
        std::error_code canon_ec;
        std::string canonical = std::filesystem::weakly_canonical(command.path, canon_ec).string();
        if (!quarantine_prefix_.empty() &&
            util::is_subpath(canon_ec ? command.path : canonical, quarantine_prefix_)) {
            return ipc::Reply{false,
                              "path is inside the quarantine store; delete it from there",
                              "error",
                              "",
                              {}};
        }
        std::error_code ec;
        if (!std::filesystem::exists(command.path, ec)) {
            return ipc::Reply{false, "path does not exist: " + command.path, "error", "", {}};
        }
        if (std::filesystem::is_directory(command.path, ec)) {
            return ipc::Reply{
                false, "refusing to delete a directory: " + command.path, "error", "", {}};
        }
        if (!std::filesystem::remove(command.path, ec) || ec) {
            return ipc::Reply{
                false, "could not delete " + command.path + ": " + ec.message(), "error", "", {}};
        }
        return ipc::Reply{true, "deleted " + command.path, "", "", {}};
    }

    case ipc::CommandKind::GetStatus: {
        std::string detail = "scanned=" + std::to_string(scanned_count_) +
                             " threats=" + std::to_string(threat_count_) +
                             " realtime=" + (config_.realtime && !paused_ ? "on" : "off");
        return ipc::Reply{true, detail, "", "", {}};
    }

    case ipc::CommandKind::Pause:
        paused_ = true;
        return ipc::Reply{true, "monitoring paused", "", "", {}};

    case ipc::CommandKind::Resume:
        paused_ = false;
        return ipc::Reply{true, "monitoring resumed", "", "", {}};

    case ipc::CommandKind::QuarantinePath: {
        if (!quarantine_) {
            return ipc::Reply{
                false, "quarantine disabled; start with --quarantine <dir>", "error", "", {}};
        }
        std::error_code canon_ec;
        std::string canonical = std::filesystem::weakly_canonical(command.path, canon_ec).string();
        if (util::is_subpath(canon_ec ? command.path : canonical, quarantine_prefix_)) {
            return ipc::Reply{
                false, "path is already inside the quarantine store", "error", "", {}};
        }
        scan::ScanResult scan_result = scanner_->scan_file(command.path);
        std::string threat = (scan_result.infected() && !scan_result.threat_name.empty())
                                 ? scan_result.threat_name
                                 : "manual";
        av::quarantine::QuarantineEntry entry = quarantine_->quarantine_file(command.path, threat);
        ++threat_count_;

        ipc::Event notice;
        notice.timestamp_ms = now_ms();
        notice.kind = ipc::EventKind::ThreatDetected;
        notice.path = entry.original_path;
        notice.verdict = "infected";
        notice.threat_name = entry.threat_name;
        notice.message = "manually quarantined as " + entry.id;
        server_->broadcast(notice);

        return ipc::Reply{true, "quarantined as " + entry.id, "", entry.id, {}};
    }

    case ipc::CommandKind::QuarantineList: {
        if (!quarantine_) {
            return ipc::Reply{
                false, "quarantine disabled; start with --quarantine <dir>", "error", "", {}};
        }
        ipc::Reply reply;
        reply.ok = true;
        for (const av::quarantine::QuarantineEntry& entry : quarantine_->list()) {
            reply.items.push_back(entry.id + "\t" + entry.original_path + "\t" + entry.threat_name +
                                  "\t" + std::to_string(entry.quarantined_at));
        }
        reply.detail = std::to_string(reply.items.size()) + " quarantined entr" +
                       (reply.items.size() == 1 ? "y" : "ies");
        return reply;
    }

    case ipc::CommandKind::QuarantineRestore: {
        if (!quarantine_) {
            return ipc::Reply{
                false, "quarantine disabled; start with --quarantine <dir>", "error", "", {}};
        }
        quarantine::QuarantineEntry entry = quarantine_->get(command.path);
        quarantine_->restore(command.path);
        std::string note;
        if (exclusions_ && exclusions_->add(entry.original_path)) {
            note = " and added to exclusions";
        }
        return ipc::Reply{true, "restored " + entry.original_path + note, "", "", {}};
    }

    case ipc::CommandKind::QuarantineDelete: {
        if (!quarantine_) {
            return ipc::Reply{
                false, "quarantine disabled; start with --quarantine <dir>", "error", "", {}};
        }
        quarantine_->remove(command.path);
        return ipc::Reply{true, "deleted " + command.path, "", "", {}};
    }

    case ipc::CommandKind::ExclusionList: {
        ipc::Reply reply;
        reply.ok = true;
        if (exclusions_) {
            for (const std::string& path : exclusions_->list()) {
                std::error_code ec;
                bool is_dir = std::filesystem::is_directory(path, ec);
                reply.items.push_back(path + "\t" + (is_dir ? "dir" : "file"));
            }
        }
        reply.detail = "exclusions=" + std::to_string(reply.items.size());
        return reply;
    }

    case ipc::CommandKind::ExclusionAdd: {
        if (command.path.empty()) {
            return ipc::Reply{false, "exclusion path is empty", "error", "", {}};
        }
        bool added = exclusions_ && exclusions_->add(command.path);
        return ipc::Reply{true,
                          added ? "added to exclusions: " + command.path
                                : "already excluded: " + command.path,
                          "",
                          "",
                          {}};
    }

    case ipc::CommandKind::ExclusionRemove: {
        bool removed = exclusions_ && exclusions_->remove(command.path);
        return ipc::Reply{true,
                          removed ? "removed from exclusions: " + command.path
                                  : "not in exclusions: " + command.path,
                          "",
                          "",
                          {}};
    }
    }
    return ipc::Reply{false, "unknown command", "error", "", {}};
}

void AntivirusDaemon::run_directory_scan(std::string root, std::vector<std::string> exclusions) {
    auto is_excluded = [&exclusions](const std::string& path) {
        for (const std::string& entry : exclusions) {
            if (util::is_subpath(path, entry)) {
                return true;
            }
        }
        return false;
    };

    std::vector<std::string> files;
    try {
        for (const std::filesystem::directory_entry& entry :
             std::filesystem::recursive_directory_iterator(
                 root, std::filesystem::directory_options::skip_permission_denied)) {
            if (scan_cancel_.load()) {
                break;
            }
            if (!entry.is_regular_file()) {
                continue;
            }
            std::string path = entry.path().string();
            if (!quarantine_prefix_.empty() && util::is_subpath(path, quarantine_prefix_)) {
                continue;
            }
            if (is_excluded(path)) {
                continue;
            }
            files.push_back(std::move(path));
        }
    } catch (const std::exception&) {}

    const std::int64_t total = static_cast<std::int64_t>(files.size());
    const std::int64_t step = std::max<std::int64_t>(1, total / 200);
    std::int64_t done = 0;
    std::int64_t infected = 0;
    std::int64_t last_post = 0;
    bool cancelled = false;

    for (const std::string& target : files) {
        if (scan_cancel_.load()) {
            cancelled = true;
            break;
        }
        scan::ScanResult result = scanner_->scan_file(target);
        ++done;
        if (result.infected()) {
            ++infected;
            std::string threat = result.threat_name;
            boost::asio::post(io_, [this, target, threat] {
                ++threat_count_;
                ipc::Event ev;
                ev.timestamp_ms = now_ms();
                ev.kind = ipc::EventKind::ThreatDetected;
                ev.path = target;
                ev.verdict = "infected";
                ev.threat_name = threat;
                ev.message = "on-demand scan";
                server_->broadcast(ev);
            });
        }
        if (done - last_post >= step) {
            last_post = done;
            boost::asio::post(io_, [this, done, total, target] {
                ipc::Event ev;
                ev.timestamp_ms = now_ms();
                ev.kind = ipc::EventKind::ScanProgress;
                ev.path = target;
                ev.message = std::to_string(done) + "/" + std::to_string(total);
                server_->broadcast(ev);
            });
        }
    }

    std::string summary = std::to_string(done) + (done == 1 ? " file" : " files") + " scanned, " +
                          std::to_string(infected) + (infected == 1 ? " threat" : " threats") +
                          " found" + (cancelled ? " (cancelled)" : "");
    boost::asio::post(io_, [this, done, total, summary] {
        scanned_count_ += done;
        ipc::Event ev;
        ev.timestamp_ms = now_ms();
        ev.kind = ipc::EventKind::ScanProgress;
        ev.message = std::to_string(done) + "/" + std::to_string(total) + "\t" + summary;
        server_->broadcast(ev);
        scan_active_.store(false);
    });
}

}
