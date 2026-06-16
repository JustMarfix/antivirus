#pragma once

#include "avcore/exclusions/exclusion_store.hpp"
#include "avcore/quarantine/quarantine.hpp"
#include "avcore/scan/file_scanner.hpp"
#include "avcore/scan/signature_database.hpp"
#include "ebpf_event.hpp"
#include "ipc_server.hpp"
#include "recursive_watcher.hpp"

#ifdef AV_HAVE_YARA
#include "avcore/scan/yara_scanner.hpp"
#endif

#ifdef AV_HAVE_EBPF
#include "ebpf_monitor.hpp"
#endif

#include <atomic>
#include <boost/asio/io_context.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

/// @file daemon.hpp
/// @brief Top-level orchestration of the antivirus monitoring service.

namespace av::daemon {

/// @brief Runtime configuration for the daemon.
struct DaemonConfig {
    std::string socket_path = "/run/avdaemon.sock"; ///< IPC listening socket.
    std::string socket_group;     ///< Group granted access to the socket (empty = none).
    unsigned int socket_mode = 0; ///< Octal mode for the socket (0 = leave default).
    std::string database_path;    ///< Signature database file (optional).
    std::string watch_path;       ///< Mount to monitor (empty = none).
    std::string quarantine_dir;   ///< Quarantine store (empty = quarantine disabled).
    std::string exclusions_path;  ///< Exclusion list file (empty = default/in-memory).
    std::string yara_rules;       ///< YARA rules file (empty = no YARA scanning).
    bool realtime = false;        ///< Enable fanotify monitoring (off by default).
    bool enforce = false;  ///< Use blocking permission events that can deny access (dangerous).
    bool syscalls = false; ///< Enable the eBPF system-call monitor (needs eBPF build + privileges).
};

/// @brief Wires the scanner, the fanotify monitor and the IPC server together.
class AntivirusDaemon {
  public:
    /// @brief Build the daemon and start its IPC server and (optional) monitor.
    /// @param io ASIO context driving all asynchronous work.
    /// @param config Runtime configuration.
    /// @throws av::IoError if the IPC socket or fanotify cannot be set up.
    AntivirusDaemon(boost::asio::io_context& io, DaemonConfig config);

    /// @brief Cancel and join any background scan before teardown.
    ~AntivirusDaemon();

  private:
    ipc::Reply handle_command(const ipc::Command& command);

    /// @brief Recursively scan a directory on a worker thread, posting progress
    ///        and detections back onto the IO thread. Runs off @ref io_.
    /// @param root Directory to scan.
    /// @param exclusions Snapshot of excluded paths taken when the scan started.
    void run_directory_scan(std::string root, std::vector<std::string> exclusions);
    AccessDecision on_access(const FileAccessEvent& event);
    void wait_for_access();
    void wait_for_structure();
#ifdef AV_HAVE_EBPF
    void on_syscall(const SyscallEvent& event);
    void wait_for_syscalls();
#endif

    boost::asio::io_context& io_;
    DaemonConfig config_;
    scan::SignatureDatabase database_;
#ifdef AV_HAVE_YARA
    std::optional<scan::YaraScanner> yara_scanner_;
#endif
    std::optional<scan::FileScanner> scanner_;
    std::optional<quarantine::Quarantine> quarantine_;
    std::optional<exclusions::ExclusionStore> exclusions_;
    std::optional<IpcServer> server_;
    std::optional<RecursiveWatcher> watcher_;
    std::optional<boost::asio::posix::stream_descriptor> fan_stream_;
    std::optional<boost::asio::posix::stream_descriptor> ino_stream_;
#ifdef AV_HAVE_EBPF
    std::optional<EbpfMonitor> ebpf_;
    std::optional<boost::asio::posix::stream_descriptor> ebpf_stream_;
#endif
    std::string quarantine_prefix_;        ///< Canonical store path; never scanned/quarantined.
    std::thread scan_thread_;              ///< Worker running the current directory scan, if any.
    std::atomic<bool> scan_active_{false}; ///< True while a background scan is running.
    std::atomic<bool> scan_cancel_{false}; ///< Set to request the running scan to stop.
    bool paused_ = false;
    std::int64_t own_pid_ = 0;
    std::int64_t scanned_count_ = 0;
    std::int64_t threat_count_ = 0;
};

}
