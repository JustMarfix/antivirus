#include "app.h"
#include "desktop_notifier.hpp"
#include "ipc_client.hpp"
#ifdef AV_HAVE_SNI
#include "tray_icon.hpp"
#endif

#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <ctime>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <slint.h>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

/// @file main.cpp
/// @brief Slint GUI front-end for the antivirus daemon.
///
/// The window is organised into pages (Monitoring / Scan results / Quarantine /
/// Exclusions). The daemon's request/reply messages are untyped, so replies are
/// demultiplexed here by inspecting their detail text, and the views are kept
/// live by polling @c GetStatus and @c QuarantineList on a short timer.

namespace {

std::string format_date(std::int64_t timestamp_s) {
    std::time_t seconds = static_cast<std::time_t>(timestamp_s);
    std::tm tm_value{};
    ::localtime_r(&seconds, &tm_value);
    std::array<char, 32> buffer{};
    std::strftime(buffer.data(), buffer.size(), "%Y-%m-%d %H:%M", &tm_value);
    return std::string(buffer.data());
}

/// Count how many rows in @p model are currently ticked. Works for any of the
/// table row structs (all carry a @c selected flag).
template <class Row> int count_selected(const std::shared_ptr<slint::VectorModel<Row>>& model) {
    int n = 0;
    for (std::size_t i = 0; i < model->row_count(); ++i) {
        if (auto row = model->row_data(i); row && (*row).selected) {
            ++n;
        }
    }
    return n;
}

/// Insert a detection, or refresh the threat name of an existing row with the
/// same path. Keeps the "Scan results" list free of duplicates when real-time
/// monitoring or a rescan flags the same file repeatedly, preserving any tick.
void upsert_detection(const std::shared_ptr<slint::VectorModel<DetectionRow>>& model,
                      const DetectionRow& detection) {
    for (std::size_t i = 0; i < model->row_count(); ++i) {
        if (auto row = model->row_data(i); row && (*row).path == detection.path) {
            DetectionRow updated = *row;
            updated.threat = detection.threat;
            model->set_row_data(i, updated);
            return;
        }
    }
    model->push_back(detection);
}

/// Drop every detection whose path matches @p path (called once the user has
/// quarantined, deleted or excluded it).
void remove_detection(const std::shared_ptr<slint::VectorModel<DetectionRow>>& model,
                      const std::string& path) {
    for (std::size_t i = model->row_count(); i-- > 0;) {
        if (auto row = model->row_data(i); row && std::string((*row).path) == path) {
            model->erase(i);
        }
    }
}

/// Drop the quarantine entry with id @p id (optimistic UI removal on restore/delete).
void remove_quarantine(const std::shared_ptr<slint::VectorModel<QuarantineRow>>& model,
                       const std::string& id) {
    for (std::size_t i = model->row_count(); i-- > 0;) {
        if (auto row = model->row_data(i); row && std::string((*row).id) == id) {
            model->erase(i);
        }
    }
}

/// Drop the exclusion row whose path matches @p path (optimistic UI removal).
void remove_exclusion(const std::shared_ptr<slint::VectorModel<ExclusionRow>>& model,
                      const std::string& path) {
    for (std::size_t i = model->row_count(); i-- > 0;) {
        if (auto row = model->row_data(i); row && std::string((*row).path) == path) {
            model->erase(i);
        }
    }
}

/// Pull a non-negative integer that follows @p key in @p text, or -1 if absent.
long extract_int(const std::string& text, const std::string& key) {
    std::size_t pos = text.find(key);
    if (pos == std::string::npos) {
        return -1;
    }
    pos += key.size();
    long value = 0;
    bool any = false;
    while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
        value = value * 10 + (text[pos] - '0');
        ++pos;
        any = true;
    }
    return any ? value : -1;
}

/// Parse one tab-separated quarantine list item ("id\tpath\tthreat\tunixsecs").
QuarantineRow parse_quarantine_item(const std::string& item) {
    std::array<std::string, 4> fields{};
    std::size_t start = 0;
    for (std::size_t f = 0; f < fields.size(); ++f) {
        std::size_t tab = item.find('\t', start);
        if (tab == std::string::npos || f == fields.size() - 1) {
            fields[f] = item.substr(start);
            break;
        }
        fields[f] = item.substr(start, tab - start);
        start = tab + 1;
    }

    QuarantineRow row{}; // value-init so `selected` starts false, not indeterminate
    row.id = slint::SharedString(fields[0]);
    row.path = slint::SharedString(fields[1]);
    row.threat = slint::SharedString(fields[2]);
    std::int64_t when = 0;
    try {
        when = fields[3].empty() ? 0 : std::stoll(fields[3]);
    } catch (const std::exception&) {
        when = 0;
    }
    row.date = slint::SharedString(when > 0 ? format_date(when) : std::string("—"));
    return row;
}

/// Parse one tab-separated exclusion list item ("path\t<dir|file>").
ExclusionRow parse_exclusion_item(const std::string& item) {
    ExclusionRow row{}; // value-init so `selected` starts false, not indeterminate
    std::size_t tab = item.find('\t');
    if (tab == std::string::npos) {
        row.path = slint::SharedString(item);
        row.is_dir = false;
    } else {
        row.path = slint::SharedString(item.substr(0, tab));
        row.is_dir = (item.substr(tab + 1) == "dir");
    }
    return row;
}

/// Detach from the controlling terminal so the launching shell returns
/// immediately. Classic double-fork: the original process and the intermediate
/// child exit, while the grandchild keeps running in its own session with the
/// standard streams redirected to /dev/null. Must run before any threads or GUI
/// resources are created.
void detach_from_console() {
    pid_t pid = ::fork();
    if (pid < 0) {
        throw std::runtime_error("fork failed");
    }
    if (pid > 0) {
        ::_exit(0);
    }
    if (::setsid() < 0) {
        throw std::runtime_error("setsid failed");
    }
    ::signal(SIGHUP, SIG_IGN);
    pid = ::fork();
    if (pid < 0) {
        throw std::runtime_error("fork failed");
    }
    if (pid > 0) {
        ::_exit(0);
    }
    int fd = ::open("/dev/null", O_RDWR);
    if (fd >= 0) {
        ::dup2(fd, STDIN_FILENO);
        ::dup2(fd, STDOUT_FILENO);
        ::dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) {
            ::close(fd);
        }
    }
}

}

int main(int argc, char** argv) {
    try {
        std::string socket_path = "/run/avdaemon.sock";
        bool foreground = false;
        for (int i = 1; i < argc; ++i) {
            std::string arg(argv[i]);
            if (arg == "--socket" && i + 1 < argc) {
                socket_path = argv[i + 1];
                ++i;
            } else if (arg == "--foreground" || arg == "-f") {
                foreground = true;
            }
        }

        if (!foreground) {
            detach_from_console();
        }

        auto ui = AppWindow::create();
        auto quarantine = std::make_shared<slint::VectorModel<QuarantineRow>>();
        auto exclusions = std::make_shared<slint::VectorModel<ExclusionRow>>();
        auto detections = std::make_shared<slint::VectorModel<DetectionRow>>();
        ui->set_quarantine_items(quarantine);
        ui->set_exclusions(exclusions);
        ui->set_detections(detections);
        ui->set_conn_detail(slint::SharedString("connecting to " + socket_path));

        slint::ComponentWeakHandle<AppWindow> weak_ui = ui;
        av::client::DesktopNotifier notifier;

        auto scan_threats = std::make_shared<std::atomic<int>>(0);

        av::client::IpcClient client(
            socket_path,
            [detections, weak_ui, &notifier, scan_threats](const av::ipc::Event& event) {
                if (event.kind == av::ipc::EventKind::ScanProgress) {
                    std::string msg = event.message;
                    std::string summary;
                    if (std::size_t tab = msg.find('\t'); tab != std::string::npos) {
                        summary = msg.substr(tab + 1);
                        msg = msg.substr(0, tab);
                    }
                    long done = 0;
                    long total = 0;
                    if (std::size_t slash = msg.find('/'); slash != std::string::npos) {
                        try {
                            done = std::stol(msg.substr(0, slash));
                            total = std::stol(msg.substr(slash + 1));
                        } catch (const std::exception&) {
                        }
                    }
                    float progress =
                        (total > 0) ? static_cast<float>(done) / static_cast<float>(total) : 0.0F;
                    std::string label =
                        "Scanning " + std::to_string(done) + " / " + std::to_string(total);
                    std::string current = event.path;
                    bool finished = !summary.empty();
                    if (finished) {
                        int hits = scan_threats->exchange(0);
                        if (hits > 0) {
                            notifier.notify("LinAV: scan complete",
                                            summary.empty() ? "Scan finished" : summary, true);
                        }
                    }
                    slint::invoke_from_event_loop(
                        [weak_ui, progress, label, current, finished, summary] {
                            auto u = weak_ui.lock();
                            if (!u) {
                                return;
                            }
                            if (finished) {
                                (*u)->set_scan_active(false);
                                (*u)->set_toast(slint::SharedString("Scan: " + summary));
                            } else {
                                (*u)->set_scan_active(true);
                                (*u)->set_scan_progress(progress);
                                (*u)->set_scan_label(slint::SharedString(label));
                                (*u)->set_scan_current(slint::SharedString(current));
                            }
                        });
                    return;
                }

                if (event.kind == av::ipc::EventKind::ThreatDetected) {
                    if (event.message.find("quarantined as") == std::string::npos &&
                        !event.path.empty()) {
                        DetectionRow detection{}; // value-init: `selected` starts false
                        detection.path = slint::SharedString(event.path);
                        detection.threat = slint::SharedString(event.threat_name);
                        slint::invoke_from_event_loop(
                            [detections, detection] { upsert_detection(detections, detection); });
                    }

                    if (event.message.find("on-demand scan") != std::string::npos) {
                        scan_threats->fetch_add(1);
                    } else {
                        std::string body =
                            event.path +
                            (event.threat_name.empty() ? std::string() : "\n" + event.threat_name) +
                            (event.message.empty() ? std::string() : "\n" + event.message);
                        notifier.notify("LinAV: threat detected", body, true);
                    }
                }
            },
            [quarantine, exclusions, weak_ui, &notifier,
             scan_threats](const av::ipc::Reply& reply) {
                const std::string& detail = reply.detail;

                if (detail.rfind("exclusions=", 0) == 0) {
                    auto rows = std::make_shared<std::vector<ExclusionRow>>();
                    for (const std::string& item : reply.items) {
                        rows->push_back(parse_exclusion_item(item));
                    }
                    slint::invoke_from_event_loop([exclusions, rows, weak_ui] {
                        for (ExclusionRow& nr : *rows) {
                            for (std::size_t i = 0; i < exclusions->row_count(); ++i) {
                                auto old = exclusions->row_data(i);
                                if (old && (*old).path == nr.path) {
                                    nr.selected = (*old).selected;
                                    break;
                                }
                            }
                        }
                        exclusions->set_vector(*rows);
                        if (auto u = weak_ui.lock()) {
                            (*u)->set_exclusions_selected(count_selected(exclusions));
                        }
                    });
                    return;
                }

                if (detail.rfind("scanned=", 0) == 0) {
                    long scanned = extract_int(detail, "scanned=");
                    long threats = extract_int(detail, "threats=");
                    bool realtime = detail.find("realtime=on") != std::string::npos;
                    slint::invoke_from_event_loop([weak_ui, scanned, threats, realtime] {
                        if (auto u = weak_ui.lock()) {
                            if (scanned >= 0) {
                                (*u)->set_scanned_count(static_cast<int>(scanned));
                            }
                            if (threats >= 0) {
                                (*u)->set_threat_count(static_cast<int>(threats));
                            }
                            (*u)->set_realtime_active(realtime);
                        }
                    });
                    return;
                }

                if (detail.find("quarantined entr") != std::string::npos) {
                    auto rows = std::make_shared<std::vector<QuarantineRow>>();
                    for (const std::string& item : reply.items) {
                        rows->push_back(parse_quarantine_item(item));
                    }
                    slint::invoke_from_event_loop([weak_ui, quarantine, rows] {
                        for (QuarantineRow& nr : *rows) {
                            for (std::size_t i = 0; i < quarantine->row_count(); ++i) {
                                auto old = quarantine->row_data(i);
                                if (old && (*old).id == nr.id) {
                                    nr.selected = (*old).selected;
                                    break;
                                }
                            }
                        }
                        quarantine->set_vector(*rows);
                        if (auto u = weak_ui.lock()) {
                            (*u)->set_quarantine_enabled(true);
                            (*u)->set_quarantine_selected(count_selected(quarantine));
                        }
                    });
                    return;
                }

                if (detail.find("quarantine disabled") != std::string::npos) {
                    slint::invoke_from_event_loop([weak_ui, quarantine] {
                        if (auto u = weak_ui.lock()) {
                            (*u)->set_quarantine_enabled(false);
                        }
                        quarantine->set_vector(std::vector<QuarantineRow>{});
                    });
                    return;
                }

                if (reply.verdict == "scanning") {
                    scan_threats->store(0);
                    slint::invoke_from_event_loop([weak_ui] {
                        if (auto u = weak_ui.lock()) {
                            (*u)->set_scan_active(true);
                            (*u)->set_scan_progress(0.0F);
                            (*u)->set_scan_label(slint::SharedString("Starting scan…"));
                            (*u)->set_scan_current(slint::SharedString(""));
                        }
                    });
                    return;
                }

                std::string toast;
                if (!reply.verdict.empty()) {
                    toast = "Scan: " + reply.detail;
                    if (reply.verdict == "infected") {
                        scan_threats->store(0);
                        notifier.notify("LinAV: threat detected", reply.detail, true);
                    }
                } else {
                    toast = detail;
                }
                slint::invoke_from_event_loop([weak_ui, toast] {
                    if (auto u = weak_ui.lock()) {
                        (*u)->set_toast(slint::SharedString(toast));
                    }
                });
            },
            [weak_ui](bool connected, const std::string& detail) {
                slint::invoke_from_event_loop([weak_ui, connected, detail] {
                    if (auto u = weak_ui.lock()) {
                        (*u)->set_connected(connected);
                        (*u)->set_conn_detail(slint::SharedString(detail));
                    }
                });
            });

        ui->on_scan([&client](const slint::SharedString& path) {
            if (std::string(path).empty()) {
                return;
            }
            client.send(av::ipc::Command{av::ipc::CommandKind::ScanPath, std::string(path)});
        });
        ui->on_scan_cancel(
            [&client] { client.send(av::ipc::Command{av::ipc::CommandKind::ScanCancel, ""}); });
        ui->on_refresh_status(
            [&client] { client.send(av::ipc::Command{av::ipc::CommandKind::GetStatus, ""}); });
        ui->on_refresh_quarantine(
            [&client] { client.send(av::ipc::Command{av::ipc::CommandKind::QuarantineList, ""}); });
        ui->on_restore([&client, quarantine, &ui](const slint::SharedString& id) {
            client.send(av::ipc::Command{av::ipc::CommandKind::QuarantineRestore, std::string(id)});
            remove_quarantine(quarantine, std::string(id));
            ui->set_quarantine_selected(count_selected(quarantine));
        });
        ui->on_delete_item([&client, quarantine, &ui](const slint::SharedString& id) {
            client.send(av::ipc::Command{av::ipc::CommandKind::QuarantineDelete, std::string(id)});
            remove_quarantine(quarantine, std::string(id));
            ui->set_quarantine_selected(count_selected(quarantine));
        });
        ui->on_pause([&client] { client.send(av::ipc::Command{av::ipc::CommandKind::Pause, ""}); });
        ui->on_resume(
            [&client] { client.send(av::ipc::Command{av::ipc::CommandKind::Resume, ""}); });
        ui->on_page_selected([&client](int page) {
            if (page == 1) {
                client.send(av::ipc::Command{av::ipc::CommandKind::QuarantineList, ""});
            } else if (page == 3) {
                client.send(av::ipc::Command{av::ipc::CommandKind::ExclusionList, ""});
            } else {
                client.send(av::ipc::Command{av::ipc::CommandKind::GetStatus, ""});
            }
        });
        ui->on_quit([] { slint::quit_event_loop(); });

        ui->on_refresh_exclusions(
            [&client] { client.send(av::ipc::Command{av::ipc::CommandKind::ExclusionList, ""}); });
        ui->on_exclude_add([&client](const slint::SharedString& path) {
            if (std::string(path).empty()) {
                return;
            }
            client.send(av::ipc::Command{av::ipc::CommandKind::ExclusionAdd, std::string(path)});
            client.send(av::ipc::Command{av::ipc::CommandKind::ExclusionList, ""});
        });
        ui->on_exclude_remove([&client, exclusions, &ui](const slint::SharedString& path) {
            client.send(av::ipc::Command{av::ipc::CommandKind::ExclusionRemove, std::string(path)});
            remove_exclusion(exclusions, std::string(path));
            ui->set_exclusions_selected(count_selected(exclusions));
            client.send(av::ipc::Command{av::ipc::CommandKind::ExclusionList, ""});
        });

        ui->on_detect_quarantine([&client, detections, &ui](const slint::SharedString& path) {
            client.send(av::ipc::Command{av::ipc::CommandKind::QuarantinePath, std::string(path)});
            remove_detection(detections, std::string(path));
            ui->set_detections_selected(count_selected(detections));
        });
        ui->on_detect_delete([&client, detections, &ui](const slint::SharedString& path) {
            client.send(av::ipc::Command{av::ipc::CommandKind::DeletePath, std::string(path)});
            remove_detection(detections, std::string(path));
            ui->set_detections_selected(count_selected(detections));
        });
        ui->on_detect_exclude([&client, detections, &ui](const slint::SharedString& path) {
            client.send(av::ipc::Command{av::ipc::CommandKind::ExclusionAdd, std::string(path)});
            remove_detection(detections, std::string(path));
            ui->set_detections_selected(count_selected(detections));
        });
        ui->on_clear_detections([detections, &ui] {
            while (detections->row_count() > 0) {
                detections->erase(0);
            }
            ui->set_detections_selected(0);
        });

        ui->on_detect_toggle([detections, &ui](int index, bool on) {
            if (index < 0 || static_cast<std::size_t>(index) >= detections->row_count()) {
                return;
            }
            if (auto row = detections->row_data(static_cast<std::size_t>(index))) {
                DetectionRow updated = *row;
                updated.selected = on;
                detections->set_row_data(static_cast<std::size_t>(index), updated);
            }
            ui->set_detections_selected(count_selected(detections));
        });
        ui->on_detect_select_all([detections, &ui](bool on) {
            for (std::size_t i = 0; i < detections->row_count(); ++i) {
                if (auto row = detections->row_data(i)) {
                    DetectionRow updated = *row;
                    updated.selected = on;
                    detections->set_row_data(i, updated);
                }
            }
            ui->set_detections_selected(on ? static_cast<int>(detections->row_count()) : 0);
        });
        ui->on_detect_quarantine_selected([&client, detections, &ui] {
            for (std::size_t i = detections->row_count(); i-- > 0;) {
                if (auto row = detections->row_data(i); row && (*row).selected) {
                    client.send(av::ipc::Command{av::ipc::CommandKind::QuarantinePath,
                                                 std::string((*row).path)});
                    detections->erase(i);
                }
            }
            ui->set_detections_selected(0);
        });
        ui->on_detect_exclude_selected([&client, detections, &ui] {
            for (std::size_t i = detections->row_count(); i-- > 0;) {
                if (auto row = detections->row_data(i); row && (*row).selected) {
                    client.send(av::ipc::Command{av::ipc::CommandKind::ExclusionAdd,
                                                 std::string((*row).path)});
                    detections->erase(i);
                }
            }
            ui->set_detections_selected(0);
        });
        ui->on_detect_delete_selected([&client, detections, &ui] {
            for (std::size_t i = detections->row_count(); i-- > 0;) {
                if (auto row = detections->row_data(i); row && (*row).selected) {
                    client.send(av::ipc::Command{av::ipc::CommandKind::DeletePath,
                                                 std::string((*row).path)});
                    detections->erase(i);
                }
            }
            ui->set_detections_selected(0);
        });
        ui->on_quar_toggle([quarantine, &ui](int index, bool on) {
            if (index < 0 || static_cast<std::size_t>(index) >= quarantine->row_count()) {
                return;
            }
            if (auto row = quarantine->row_data(static_cast<std::size_t>(index))) {
                QuarantineRow updated = *row;
                updated.selected = on;
                quarantine->set_row_data(static_cast<std::size_t>(index), updated);
            }
            ui->set_quarantine_selected(count_selected(quarantine));
        });
        ui->on_quar_select_all([quarantine, &ui](bool on) {
            for (std::size_t i = 0; i < quarantine->row_count(); ++i) {
                if (auto row = quarantine->row_data(i)) {
                    QuarantineRow updated = *row;
                    updated.selected = on;
                    quarantine->set_row_data(i, updated);
                }
            }
            ui->set_quarantine_selected(on ? static_cast<int>(quarantine->row_count()) : 0);
        });
        ui->on_quar_restore_selected([&client, quarantine, &ui] {
            for (std::size_t i = quarantine->row_count(); i-- > 0;) {
                if (auto row = quarantine->row_data(i); row && (*row).selected) {
                    client.send(av::ipc::Command{av::ipc::CommandKind::QuarantineRestore,
                                                 std::string((*row).id)});
                    quarantine->erase(i);
                }
            }
            ui->set_quarantine_selected(0);
        });
        ui->on_quar_delete_selected([&client, quarantine, &ui] {
            for (std::size_t i = quarantine->row_count(); i-- > 0;) {
                if (auto row = quarantine->row_data(i); row && (*row).selected) {
                    client.send(av::ipc::Command{av::ipc::CommandKind::QuarantineDelete,
                                                 std::string((*row).id)});
                    quarantine->erase(i);
                }
            }
            ui->set_quarantine_selected(0);
        });
        ui->on_excl_toggle([exclusions, &ui](int index, bool on) {
            if (index < 0 || static_cast<std::size_t>(index) >= exclusions->row_count()) {
                return;
            }
            if (auto row = exclusions->row_data(static_cast<std::size_t>(index))) {
                ExclusionRow updated = *row;
                updated.selected = on;
                exclusions->set_row_data(static_cast<std::size_t>(index), updated);
            }
            ui->set_exclusions_selected(count_selected(exclusions));
        });
        ui->on_excl_select_all([exclusions, &ui](bool on) {
            for (std::size_t i = 0; i < exclusions->row_count(); ++i) {
                if (auto row = exclusions->row_data(i)) {
                    ExclusionRow updated = *row;
                    updated.selected = on;
                    exclusions->set_row_data(i, updated);
                }
            }
            ui->set_exclusions_selected(on ? static_cast<int>(exclusions->row_count()) : 0);
        });
        ui->on_excl_remove_selected([&client, exclusions, &ui] {
            for (std::size_t i = exclusions->row_count(); i-- > 0;) {
                if (auto row = exclusions->row_data(i); row && (*row).selected) {
                    client.send(av::ipc::Command{av::ipc::CommandKind::ExclusionRemove,
                                                 std::string((*row).path)});
                    exclusions->erase(i);
                }
            }
            ui->set_exclusions_selected(0);
            client.send(av::ipc::Command{av::ipc::CommandKind::ExclusionList, ""});
        });

        bool close_to_tray = false;
#ifdef AV_HAVE_SNI
        std::unique_ptr<av::client::TrayIcon> tray;
        try {
            tray = std::make_unique<av::client::TrayIcon>(
                [weak_ui] {
                    slint::invoke_from_event_loop([weak_ui] {
                        if (auto u = weak_ui.lock()) {
                            (*u)->window().show();
                        }
                    });
                },
                [] { slint::invoke_from_event_loop([] { slint::quit_event_loop(); }); });
        } catch (const std::exception& e) {
            std::cerr << "tray icon unavailable: " << e.what() << '\n';
        }
        av::client::TrayIcon* tray_ptr = tray.get();
        close_to_tray = (tray_ptr != nullptr);
#endif

        if (close_to_tray) {
            ui->window().on_close_requested([] { return slint::CloseRequestResponse::HideWindow; });
        } else {
            ui->window().on_close_requested([] {
                slint::quit_event_loop();
                return slint::CloseRequestResponse::HideWindow;
            });
        }

        slint::Timer poll_timer;
        poll_timer.start(
            slint::TimerMode::Repeated, std::chrono::milliseconds(2000),
            [&client, &ui
#ifdef AV_HAVE_SNI
             ,
             tray_ptr
#endif
        ] {
                if (client.connected()) {
                    client.send(av::ipc::Command{av::ipc::CommandKind::GetStatus, ""});
                    client.send(av::ipc::Command{av::ipc::CommandKind::QuarantineList, ""});
                    if (ui->get_page() == 3) {
                        client.send(av::ipc::Command{av::ipc::CommandKind::ExclusionList, ""});
                    }
                }
#ifdef AV_HAVE_SNI
                if (tray_ptr != nullptr) {
                    tray_ptr->set_safe(ui->get_active_threats() == 0);
                }
#endif
            });

        ui->show();
        slint::run_event_loop(slint::EventLoopMode::RunUntilQuit);
        ui->hide();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "avclient fatal: " << e.what() << '\n';
        return 1;
    }
}
