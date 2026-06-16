#include "avcore/error.hpp"
#include "daemon.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <iostream>
#include <string>
#include <vector>

/// @file main.cpp
/// @brief Entry point of the antivirus monitoring daemon.

namespace {

void print_usage(const char* program) {
    std::cerr << "Usage: " << program << " [options]\n"
              << "  --socket <path>   IPC socket path (default /run/avdaemon.sock)\n"
              << "  --socket-group <g> Grant group <g> access to the socket (mode 0660),\n"
              << "                    so an unprivileged client can connect without root.\n"
              << "  --socket-mode <m> Octal permission mode for the socket (e.g. 0660).\n"
              << "  --db <file>       Signature database file\n"
              << "  --yara <path>     YARA rules file, or a directory of *.yar/*.yara\n"
              << "                    files loaded recursively (requires a YARA build).\n"
              << "  --watch <dir>     Recursively monitor directory <dir> in NOTIFY mode\n"
              << "                    (non-blocking, safe). Subdirectories created or removed\n"
              << "                    later are tracked automatically. Without this, the\n"
              << "                    daemon only serves IPC.\n"
              << "  --quarantine <d>  Enable quarantine, storing isolated files under <d>.\n"
              << "                    Detected threats are auto-quarantined. Keep <d> OUTSIDE\n"
              << "                    any --watch subtree.\n"
              << "  --exclusions <f>  Persist the scan-exclusion list to file <f> (default:\n"
              << "                    <quarantine>/exclusions.list when quarantine is on).\n"
              << "  --syscalls        Enable the eBPF system-call monitor (execve/fork/\n"
              << "                    ptrace/mmap-PROT_EXEC). Requires an eBPF-enabled build\n"
              << "                    and privileges; executed binaries are scanned.\n"
              << "  --enforce         Use BLOCKING permission events that can DENY access to\n"
              << "                    files in the watched subtree. Requires --watch. A slow\n"
              << "                    or crashing daemon can delay opens within that subtree,\n"
              << "                    so keep it dedicated and avoid busy/system directories.\n";
}

}

int main(int argc, char** argv) {
    try {
        std::vector<std::string> args(argv + 1, argv + argc);
        av::daemon::DaemonConfig config;

        for (std::size_t i = 0; i < args.size(); ++i) {
            const std::string& arg = args[i];
            if (arg == "--socket" && i + 1 < args.size()) {
                config.socket_path = args[++i];
            } else if (arg == "--socket-group" && i + 1 < args.size()) {
                config.socket_group = args[++i];
            } else if (arg == "--socket-mode" && i + 1 < args.size()) {
                config.socket_mode = static_cast<unsigned int>(std::stoul(args[++i], nullptr, 8));
            } else if (arg == "--db" && i + 1 < args.size()) {
                config.database_path = args[++i];
            } else if (arg == "--yara" && i + 1 < args.size()) {
                config.yara_rules = args[++i];
            } else if (arg == "--watch" && i + 1 < args.size()) {
                config.watch_path = args[++i];
                config.realtime = true;
            } else if (arg == "--quarantine" && i + 1 < args.size()) {
                config.quarantine_dir = args[++i];
            } else if (arg == "--exclusions" && i + 1 < args.size()) {
                config.exclusions_path = args[++i];
            } else if (arg == "--enforce") {
                config.enforce = true;
            } else if (arg == "--syscalls") {
                config.syscalls = true;
            } else if (arg == "--help" || arg == "-h") {
                print_usage(argv[0]);
                return 0;
            } else {
                print_usage(argv[0]);
                return 2;
            }
        }

        if (config.enforce && !config.realtime) {
            std::cerr << "avdaemon: --enforce requires --watch <path>\n";
            return 2;
        }
#ifndef AV_HAVE_EBPF
        if (config.syscalls) {
            std::cerr << "avdaemon: --syscalls requires a build with -DAV_ENABLE_EBPF=ON\n";
            return 2;
        }
#endif
#ifndef AV_HAVE_YARA
        if (!config.yara_rules.empty()) {
            std::cerr << "avdaemon: --yara requires a build with -DAV_ENABLE_YARA=ON\n";
            return 2;
        }
#endif
        if (config.enforce) {
            std::cerr
                << "avdaemon: WARNING: enforcing mode places BLOCKING permission marks across the "
                   "subtree '"
                << config.watch_path
                << "'.\n            Opens of files there wait for this daemon; a stall here\n     "
                   "       can hang access to that subtree. Keep it dedicated; never a system "
                   "path.\n";
        }

        boost::asio::io_context io;
        av::daemon::AntivirusDaemon daemon(io, config);

        boost::asio::signal_set signals(io, SIGINT, SIGTERM);
        signals.async_wait([&io](const boost::system::error_code&, int) { io.stop(); });

        std::cout << "avdaemon: listening on " << config.socket_path;
        if (config.realtime) {
            std::cout << " (monitoring '" << config.watch_path << "', "
                      << (config.enforce ? "ENFORCING/blocking" : "notify-only") << ")";
        } else {
            std::cout << " (IPC only)";
        }
        std::cout << '\n';

        io.run();
        std::cout << "avdaemon: shutting down\n";
        return 0;
    } catch (const av::AvException& e) {
        std::cerr << "avdaemon error: " << e.what() << '\n';
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "avdaemon fatal: " << e.what() << '\n';
        return 1;
    }
}
