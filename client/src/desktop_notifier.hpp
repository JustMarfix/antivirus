#pragma once

#include <string>

/// @file desktop_notifier.hpp
/// @brief Minimal desktop-notification helper.

namespace av::client {

/// @brief Raises freedesktop desktop notifications via the `notify-send` tool.
///
/// The GUI client runs inside the user's session, which is the only context with
/// access to the session notification bus (the privileged daemon cannot reach
/// it). Notifications are delivered by spawning `notify-send`; if that tool is
/// unavailable the call degrades silently. No shell is involved, so notification
/// text cannot be misinterpreted as a command.
class DesktopNotifier {
  public:
    /// @brief Show a desktop notification.
    /// @param summary Short title line.
    /// @param body Longer description.
    /// @param critical If true, request critical (sticky) urgency.
    void notify(const std::string& summary, const std::string& body, bool critical) const noexcept;
};

}
