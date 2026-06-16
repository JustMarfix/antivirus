#pragma once

#include <cstdint>
#include <string>
#include <vector>

/// @file message.hpp
/// @brief Message types exchanged between the daemon and the GUI client.

namespace av::ipc {

/// @brief Category of an event pushed from the daemon to clients.
enum class EventKind {
    FileOpen,       ///< A file was opened.
    FileExec,       ///< A file was executed.
    FileModify,     ///< A file was created or modified.
    ProcessStart,   ///< A new process was observed.
    ThreatDetected, ///< A scan flagged an object as malicious.
    ScanProgress,   ///< Async scan progress; @ref Event::message = "done/total"[+"\tsummary"].
    Info            ///< Informational/diagnostic message.
};

/// @brief An asynchronous notification from the daemon.
struct Event {
    std::int64_t timestamp_ms = 0;    ///< Unix time in milliseconds.
    EventKind kind = EventKind::Info; ///< Event category.
    std::string path;                 ///< File or process path involved.
    std::int64_t pid = 0;             ///< Originating process id, if known.
    std::string verdict;              ///< Scan verdict ("clean"/"infected"/"error").
    std::string threat_name;          ///< Threat name when applicable.
    std::string message;              ///< Free-form description.
};

/// @brief Category of a command sent from a client to the daemon.
enum class CommandKind {
    Ping,              ///< Liveness probe.
    ScanPath,          ///< Request an on-demand scan of @ref Command::path.
    ScanCancel,        ///< Cancel the in-progress asynchronous (directory) scan.
    DeletePath,        ///< Permanently delete the file at @ref Command::path from disk.
    GetStatus,         ///< Request a status snapshot.
    Pause,             ///< Pause real-time monitoring.
    Resume,            ///< Resume real-time monitoring.
    QuarantinePath,    ///< Move @ref Command::path into quarantine.
    QuarantineList,    ///< List quarantined entries.
    QuarantineRestore, ///< Restore the entry whose id is in @ref Command::path.
    QuarantineDelete,  ///< Permanently delete the entry id in @ref Command::path.
    ExclusionList,     ///< List paths excluded from scanning.
    ExclusionAdd,      ///< Exclude the file or directory in @ref Command::path.
    ExclusionRemove    ///< Stop excluding the path in @ref Command::path.
};

/// @brief A request from a client to the daemon.
struct Command {
    CommandKind kind = CommandKind::Ping; ///< Requested action.
    std::string path;                     ///< Target path, or quarantine entry id.
};

/// @brief A synchronous response to a @ref Command.
struct Reply {
    bool ok = true;                 ///< Whether the command succeeded.
    std::string detail;             ///< Human-readable detail or error text.
    std::string verdict;            ///< Scan verdict for ScanPath replies.
    std::string threat_name;        ///< Threat name for ScanPath replies.
    std::vector<std::string> items; ///< List payload (e.g. quarantine entries).
};

}
