#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>

struct sd_bus;
struct sd_bus_slot;

/// @file tray_icon.hpp
/// @brief System-tray presence for the GUI client.

namespace av::client {

/// @brief A freedesktop StatusNotifierItem (SNI) tray icon backed by sd-bus.
///
/// The item exposes itself on the user's session bus as
/// `org.kde.StatusNotifierItem` plus a small `com.canonical.dbusmenu` context
/// menu ("Open LinAV" / "Quit"). A dedicated thread drives the sd-bus event
/// loop. Left-clicking the icon or choosing "Open LinAV" invokes
/// @ref on_activate; "Quit" invokes @ref on_quit. Both callbacks run on the
/// tray thread, so the GUI layer must marshal them onto its own event loop.
///
/// The icon reflects protection state: a "secure" themed icon when no threats
/// are active, and a "needs attention" icon (with NeedsAttention status) when
/// threats are present.
class TrayIcon {
  public:
    /// @brief A user-triggered action with no arguments.
    using ActionCallback = std::function<void()>;

    /// @brief Register the tray item and start the background bus loop.
    /// @param on_activate Invoked when the user asks to show the window.
    /// @param on_quit Invoked when the user asks to quit the application.
    /// @throws std::runtime_error if the session bus is unavailable or the item
    ///         cannot be registered.
    TrayIcon(ActionCallback on_activate, ActionCallback on_quit);

    /// @brief Stop the bus loop and release the tray item.
    ~TrayIcon();

    TrayIcon(const TrayIcon&) = delete;
    TrayIcon& operator=(const TrayIcon&) = delete;

    /// @brief Update the protection state shown by the icon.
    /// @param safe True when no threats are active, false otherwise.
    void set_safe(bool safe) noexcept;

    /// @cond INTERNAL
    bool safe() const noexcept { return safe_.load(); }
    void trigger_activate() const;
    void trigger_quit() const;
    /// @endcond

  private:
    void run();
    void register_with_watcher();

    struct BusDeleter {
        void operator()(sd_bus* bus) const noexcept;
    };
    struct SlotDeleter {
        void operator()(sd_bus_slot* slot) const noexcept;
    };

    ActionCallback on_activate_;
    ActionCallback on_quit_;
    std::string name_;
    std::unique_ptr<sd_bus, BusDeleter> bus_;
    std::unique_ptr<sd_bus_slot, SlotDeleter> sni_slot_;
    std::unique_ptr<sd_bus_slot, SlotDeleter> menu_slot_;
    std::atomic<bool> safe_{true};
    std::atomic<bool> dirty_{false};
    std::atomic<bool> running_{true};
    std::thread worker_;
};

}
