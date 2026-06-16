#include "tray_icon.hpp"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <systemd/sd-bus.h>
#include <unistd.h>

/// @file tray_icon.cpp
/// @brief StatusNotifierItem + DBusMenu implementation over sd-bus.

namespace av::client {

namespace {

constexpr const char* kSniPath = "/StatusNotifierItem";
constexpr const char* kSniIface = "org.kde.StatusNotifierItem";
constexpr const char* kMenuPath = "/MenuBar";
constexpr const char* kMenuIface = "com.canonical.dbusmenu";

// Stable menu entry identifiers shared by the layout and event handlers.
constexpr int kItemOpen = 1;
constexpr int kItemQuit = 2;

const char* item_label(int id) {
    switch (id) {
    case kItemOpen:
        return "Open LinAV";
    case kItemQuit:
        return "Quit";
    default:
        return "";
    }
}

// ---- small RAII reply holder ----------------------------------------------
struct MsgDeleter {
    void operator()(sd_bus_message* m) const noexcept { sd_bus_message_unref(m); }
};
using MsgPtr = std::unique_ptr<sd_bus_message, MsgDeleter>;

// ---- a{sv} dictionary helpers ---------------------------------------------
int dict_str(sd_bus_message* m, const char* key, const char* value) {
    int r = sd_bus_message_open_container(m, 'e', "sv");
    if (r < 0) {
        return r;
    }
    r = sd_bus_message_append(m, "s", key);
    if (r < 0) {
        return r;
    }
    r = sd_bus_message_append(m, "v", "s", value);
    if (r < 0) {
        return r;
    }
    return sd_bus_message_close_container(m);
}

int dict_bool(sd_bus_message* m, const char* key, int value) {
    int r = sd_bus_message_open_container(m, 'e', "sv");
    if (r < 0) {
        return r;
    }
    r = sd_bus_message_append(m, "s", key);
    if (r < 0) {
        return r;
    }
    r = sd_bus_message_append(m, "v", "b", value);
    if (r < 0) {
        return r;
    }
    return sd_bus_message_close_container(m);
}

// Append the a{sv} property dictionary for a single menu node.
int append_item_props(sd_bus_message* m, int id) {
    int r = sd_bus_message_open_container(m, 'a', "{sv}");
    if (r < 0) {
        return r;
    }
    if (id == 0) {
        r = dict_str(m, "children-display", "submenu");
        if (r < 0) {
            return r;
        }
    } else {
        r = dict_str(m, "label", item_label(id));
        if (r < 0) {
            return r;
        }
        r = dict_bool(m, "enabled", 1);
        if (r < 0) {
            return r;
        }
        r = dict_bool(m, "visible", 1);
        if (r < 0) {
            return r;
        }
    }
    return sd_bus_message_close_container(m);
}

// Recursively append a menu node as the DBusMenu (ia{sv}av) structure. Only the
// root (id 0) carries children.
int append_menu_node(sd_bus_message* m, int id) {
    int r = sd_bus_message_open_container(m, 'r', "ia{sv}av");
    if (r < 0) {
        return r;
    }
    r = sd_bus_message_append(m, "i", id);
    if (r < 0) {
        return r;
    }
    r = append_item_props(m, id);
    if (r < 0) {
        return r;
    }
    r = sd_bus_message_open_container(m, 'a', "v");
    if (r < 0) {
        return r;
    }
    if (id == 0) {
        for (int child : {kItemOpen, kItemQuit}) {
            r = sd_bus_message_open_container(m, 'v', "(ia{sv}av)");
            if (r < 0) {
                return r;
            }
            r = append_menu_node(m, child);
            if (r < 0) {
                return r;
            }
            r = sd_bus_message_close_container(m);
            if (r < 0) {
                return r;
            }
        }
    }
    r = sd_bus_message_close_container(m);
    if (r < 0) {
        return r;
    }
    return sd_bus_message_close_container(m);
}

void dispatch_menu_event(TrayIcon* self, int id, const char* event_id) {
    if (std::strcmp(event_id, "clicked") != 0) {
        return;
    }
    if (id == kItemOpen) {
        self->trigger_activate();
    } else if (id == kItemQuit) {
        self->trigger_quit();
    }
}

// ===========================================================================
//  org.kde.StatusNotifierItem property getters and methods
// ===========================================================================

int prop_category(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply, void*,
                  sd_bus_error*) {
    return sd_bus_message_append(reply, "s", "ApplicationStatus");
}

int prop_id(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply, void*,
            sd_bus_error*) {
    return sd_bus_message_append(reply, "s", "linav");
}

int prop_title(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply, void*,
               sd_bus_error*) {
    return sd_bus_message_append(reply, "s", "LinAV");
}

int prop_status(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply,
                void* userdata, sd_bus_error*) {
    auto* self = static_cast<TrayIcon*>(userdata);
    return sd_bus_message_append(reply, "s", self->safe() ? "Active" : "NeedsAttention");
}

int prop_window_id(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply, void*,
                   sd_bus_error*) {
    return sd_bus_message_append(reply, "u", 0U);
}

int prop_icon_name(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply,
                   void* userdata, sd_bus_error*) {
    auto* self = static_cast<TrayIcon*>(userdata);
    return sd_bus_message_append(reply, "s", self->safe() ? "security-high" : "security-low");
}

int prop_attention_icon(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply,
                        void*, sd_bus_error*) {
    return sd_bus_message_append(reply, "s", "security-low");
}

int prop_empty_string(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply, void*,
                      sd_bus_error*) {
    return sd_bus_message_append(reply, "s", "");
}

int prop_empty_pixmap(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply, void*,
                      sd_bus_error*) {
    int r = sd_bus_message_open_container(reply, 'a', "(iiay)");
    if (r < 0) {
        return r;
    }
    return sd_bus_message_close_container(reply);
}

int prop_tooltip(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply,
                 void* userdata, sd_bus_error*) {
    auto* self = static_cast<TrayIcon*>(userdata);
    int r = sd_bus_message_open_container(reply, 'r', "sa(iiay)ss");
    if (r < 0) {
        return r;
    }
    r = sd_bus_message_append(reply, "s", self->safe() ? "security-high" : "security-low");
    if (r < 0) {
        return r;
    }
    r = sd_bus_message_open_container(reply, 'a', "(iiay)");
    if (r < 0) {
        return r;
    }
    r = sd_bus_message_close_container(reply);
    if (r < 0) {
        return r;
    }
    r = sd_bus_message_append(reply, "s", "LinAV");
    if (r < 0) {
        return r;
    }
    r = sd_bus_message_append(reply, "s",
                              self->safe() ? "No active threats" : "Threats need attention");
    if (r < 0) {
        return r;
    }
    return sd_bus_message_close_container(reply);
}

int prop_item_is_menu(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply, void*,
                      sd_bus_error*) {
    return sd_bus_message_append(reply, "b", 0);
}

int prop_menu(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply, void*,
              sd_bus_error*) {
    return sd_bus_message_append(reply, "o", kMenuPath);
}

int method_activate(sd_bus_message* m, void* userdata, sd_bus_error*) {
    static_cast<TrayIcon*>(userdata)->trigger_activate();
    return sd_bus_reply_method_return(m, "");
}

int method_noop(sd_bus_message* m, void*, sd_bus_error*) {
    return sd_bus_reply_method_return(m, "");
}

// ===========================================================================
//  com.canonical.dbusmenu property getters and methods
// ===========================================================================

int menu_prop_version(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply, void*,
                      sd_bus_error*) {
    return sd_bus_message_append(reply, "u", 3U);
}

int menu_prop_status(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply, void*,
                     sd_bus_error*) {
    return sd_bus_message_append(reply, "s", "normal");
}

int menu_prop_text_direction(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply,
                             void*, sd_bus_error*) {
    return sd_bus_message_append(reply, "s", "ltr");
}

int menu_prop_icon_theme_path(sd_bus*, const char*, const char*, const char*, sd_bus_message* reply,
                              void*, sd_bus_error*) {
    int r = sd_bus_message_open_container(reply, 'a', "s");
    if (r < 0) {
        return r;
    }
    return sd_bus_message_close_container(reply);
}

int menu_get_layout(sd_bus_message* m, void*, sd_bus_error*) {
    sd_bus_message* raw = nullptr;
    int r = sd_bus_message_new_method_return(m, &raw);
    if (r < 0) {
        return r;
    }
    MsgPtr reply(raw);
    r = sd_bus_message_append(reply.get(), "u", 1U);
    if (r < 0) {
        return r;
    }
    r = append_menu_node(reply.get(), 0);
    if (r < 0) {
        return r;
    }
    r = sd_bus_send(nullptr, reply.get(), nullptr);
    return r < 0 ? r : 1;
}

int menu_get_group_properties(sd_bus_message* m, void*, sd_bus_error*) {
    sd_bus_message* raw = nullptr;
    int r = sd_bus_message_new_method_return(m, &raw);
    if (r < 0) {
        return r;
    }
    MsgPtr reply(raw);
    r = sd_bus_message_open_container(reply.get(), 'a', "(ia{sv})");
    if (r < 0) {
        return r;
    }
    for (int id : {0, kItemOpen, kItemQuit}) {
        r = sd_bus_message_open_container(reply.get(), 'r', "ia{sv}");
        if (r < 0) {
            return r;
        }
        r = sd_bus_message_append(reply.get(), "i", id);
        if (r < 0) {
            return r;
        }
        r = append_item_props(reply.get(), id);
        if (r < 0) {
            return r;
        }
        r = sd_bus_message_close_container(reply.get());
        if (r < 0) {
            return r;
        }
    }
    r = sd_bus_message_close_container(reply.get());
    if (r < 0) {
        return r;
    }
    r = sd_bus_send(nullptr, reply.get(), nullptr);
    return r < 0 ? r : 1;
}

int menu_get_property(sd_bus_message* m, void*, sd_bus_error*) {
    int id = 0;
    const char* name = nullptr;
    int r = sd_bus_message_read(m, "is", &id, &name);
    if (r < 0) {
        return r;
    }
    const char* value = (name != nullptr && std::strcmp(name, "label") == 0) ? item_label(id) : "";
    return sd_bus_reply_method_return(m, "v", "s", value);
}

int menu_event(sd_bus_message* m, void* userdata, sd_bus_error*) {
    int id = 0;
    const char* event_id = nullptr;
    int r = sd_bus_message_read(m, "is", &id, &event_id);
    if (r < 0) {
        return r;
    }
    r = sd_bus_message_skip(m, "v");
    if (r < 0) {
        return r;
    }
    if (event_id != nullptr) {
        dispatch_menu_event(static_cast<TrayIcon*>(userdata), id, event_id);
    }
    return sd_bus_reply_method_return(m, "");
}

int menu_event_group(sd_bus_message* m, void* userdata, sd_bus_error*) {
    auto* self = static_cast<TrayIcon*>(userdata);
    int r = sd_bus_message_enter_container(m, 'a', "(isvu)");
    if (r < 0) {
        return r;
    }
    while ((r = sd_bus_message_enter_container(m, 'r', "isvu")) > 0) {
        int id = 0;
        const char* event_id = nullptr;
        if (sd_bus_message_read(m, "is", &id, &event_id) >= 0) {
            sd_bus_message_skip(m, "vu");
            if (event_id != nullptr) {
                dispatch_menu_event(self, id, event_id);
            }
        }
        sd_bus_message_exit_container(m);
    }
    if (r < 0) {
        return r;
    }
    sd_bus_message_exit_container(m);

    sd_bus_message* raw = nullptr;
    r = sd_bus_message_new_method_return(m, &raw);
    if (r < 0) {
        return r;
    }
    MsgPtr reply(raw);
    r = sd_bus_message_open_container(reply.get(), 'a', "i");
    if (r < 0) {
        return r;
    }
    r = sd_bus_message_close_container(reply.get());
    if (r < 0) {
        return r;
    }
    r = sd_bus_send(nullptr, reply.get(), nullptr);
    return r < 0 ? r : 1;
}

int menu_about_to_show(sd_bus_message* m, void*, sd_bus_error*) {
    return sd_bus_reply_method_return(m, "b", 0);
}

int menu_about_to_show_group(sd_bus_message* m, void*, sd_bus_error*) {
    sd_bus_message* raw = nullptr;
    int r = sd_bus_message_new_method_return(m, &raw);
    if (r < 0) {
        return r;
    }
    MsgPtr reply(raw);
    for (int i = 0; i < 2; ++i) {
        r = sd_bus_message_open_container(reply.get(), 'a', "i");
        if (r < 0) {
            return r;
        }
        r = sd_bus_message_close_container(reply.get());
        if (r < 0) {
            return r;
        }
    }
    r = sd_bus_send(nullptr, reply.get(), nullptr);
    return r < 0 ? r : 1;
}

// clang-format off
const sd_bus_vtable kSniVtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Category", "s", prop_category, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Id", "s", prop_id, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Title", "s", prop_title, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Status", "s", prop_status, 0, 0),
    SD_BUS_PROPERTY("WindowId", "u", prop_window_id, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("IconName", "s", prop_icon_name, 0, 0),
    SD_BUS_PROPERTY("OverlayIconName", "s", prop_empty_string, 0, 0),
    SD_BUS_PROPERTY("AttentionIconName", "s", prop_attention_icon, 0, 0),
    SD_BUS_PROPERTY("IconPixmap", "a(iiay)", prop_empty_pixmap, 0, 0),
    SD_BUS_PROPERTY("ToolTip", "(sa(iiay)ss)", prop_tooltip, 0, 0),
    SD_BUS_PROPERTY("ItemIsMenu", "b", prop_item_is_menu, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Menu", "o", prop_menu, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_METHOD("Activate", "ii", "", method_activate, 0),
    SD_BUS_METHOD("SecondaryActivate", "ii", "", method_activate, 0),
    SD_BUS_METHOD("ContextMenu", "ii", "", method_noop, 0),
    SD_BUS_METHOD("Scroll", "is", "", method_noop, 0),
    SD_BUS_SIGNAL("NewIcon", "", 0),
    SD_BUS_SIGNAL("NewAttentionIcon", "", 0),
    SD_BUS_SIGNAL("NewToolTip", "", 0),
    SD_BUS_SIGNAL("NewStatus", "s", 0),
    SD_BUS_VTABLE_END,
};

const sd_bus_vtable kMenuVtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_PROPERTY("Version", "u", menu_prop_version, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("Status", "s", menu_prop_status, 0, 0),
    SD_BUS_PROPERTY("TextDirection", "s", menu_prop_text_direction, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_PROPERTY("IconThemePath", "as", menu_prop_icon_theme_path, 0, SD_BUS_VTABLE_PROPERTY_CONST),
    SD_BUS_METHOD("GetLayout", "iias", "u(ia{sv}av)", menu_get_layout, 0),
    SD_BUS_METHOD("GetGroupProperties", "aias", "a(ia{sv})", menu_get_group_properties, 0),
    SD_BUS_METHOD("GetProperty", "is", "v", menu_get_property, 0),
    SD_BUS_METHOD("Event", "isvu", "", menu_event, 0),
    SD_BUS_METHOD("EventGroup", "a(isvu)", "ai", menu_event_group, 0),
    SD_BUS_METHOD("AboutToShow", "i", "b", menu_about_to_show, 0),
    SD_BUS_METHOD("AboutToShowGroup", "ai", "aiai", menu_about_to_show_group, 0),
    SD_BUS_SIGNAL("ItemsPropertiesUpdated", "a(ia{sv})a(ias)", 0),
    SD_BUS_SIGNAL("LayoutUpdated", "ui", 0),
    SD_BUS_SIGNAL("ItemActivationRequested", "iu", 0),
    SD_BUS_VTABLE_END,
};
// clang-format on

}

void TrayIcon::BusDeleter::operator()(sd_bus* bus) const noexcept {
    sd_bus_flush_close_unref(bus);
}

void TrayIcon::SlotDeleter::operator()(sd_bus_slot* slot) const noexcept {
    sd_bus_slot_unref(slot);
}

TrayIcon::TrayIcon(ActionCallback on_activate, ActionCallback on_quit)
    : on_activate_(std::move(on_activate)), on_quit_(std::move(on_quit)),
      name_("org.kde.StatusNotifierItem-" + std::to_string(::getpid()) + "-1") {
    sd_bus* raw_bus = nullptr;
    int r = sd_bus_open_user(&raw_bus);
    if (r < 0) {
        throw std::runtime_error("tray: cannot connect to session bus: " +
                                 std::string(std::strerror(-r)));
    }
    bus_.reset(raw_bus);

    sd_bus_slot* slot = nullptr;
    r = sd_bus_add_object_vtable(bus_.get(), &slot, kSniPath, kSniIface, kSniVtable, this);
    if (r < 0) {
        throw std::runtime_error("tray: cannot export StatusNotifierItem: " +
                                 std::string(std::strerror(-r)));
    }
    sni_slot_.reset(slot);

    slot = nullptr;
    r = sd_bus_add_object_vtable(bus_.get(), &slot, kMenuPath, kMenuIface, kMenuVtable, this);
    if (r < 0) {
        throw std::runtime_error("tray: cannot export DBusMenu: " + std::string(std::strerror(-r)));
    }
    menu_slot_.reset(slot);

    r = sd_bus_request_name(bus_.get(), name_.c_str(), 0);
    if (r < 0) {
        throw std::runtime_error("tray: cannot acquire bus name: " +
                                 std::string(std::strerror(-r)));
    }

    register_with_watcher();
    worker_ = std::thread([this] { run(); });
}

TrayIcon::~TrayIcon() {
    running_.store(false);
    if (worker_.joinable()) {
        worker_.join();
    }
}

void TrayIcon::register_with_watcher() {
    sd_bus_error error = SD_BUS_ERROR_NULL;
    sd_bus_message* raw_reply = nullptr;
    sd_bus_call_method(bus_.get(), "org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher",
                       "org.kde.StatusNotifierWatcher", "RegisterStatusNotifierItem", &error,
                       &raw_reply, "s", name_.c_str());
    sd_bus_error_free(&error);
    if (raw_reply != nullptr) {
        sd_bus_message_unref(raw_reply);
    }
}

void TrayIcon::run() {
    while (running_.load()) {
        int r = sd_bus_process(bus_.get(), nullptr);
        if (r < 0) {
            break;
        }
        if (r > 0) {
            continue; // more work may be queued
        }
        if (dirty_.exchange(false)) {
            const char* status = safe_.load() ? "Active" : "NeedsAttention";
            sd_bus_emit_signal(bus_.get(), kSniPath, kSniIface, "NewStatus", "s", status);
            sd_bus_emit_signal(bus_.get(), kSniPath, kSniIface, "NewIcon", "");
            sd_bus_emit_signal(bus_.get(), kSniPath, kSniIface, "NewAttentionIcon", "");
            sd_bus_emit_signal(bus_.get(), kSniPath, kSniIface, "NewToolTip", "");
        }
        r = sd_bus_wait(bus_.get(), 250000);
        if (r < 0 && r != -EINTR) {
            break;
        }
    }
}

void TrayIcon::set_safe(bool safe) noexcept {
    if (safe_.exchange(safe) != safe) {
        dirty_.store(true);
    }
}

void TrayIcon::trigger_activate() const {
    if (on_activate_) {
        on_activate_();
    }
}

void TrayIcon::trigger_quit() const {
    if (on_quit_) {
        on_quit_();
    }
}

}
