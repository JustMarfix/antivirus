#include "avipc/codec.hpp"

#include "avcore/error.hpp"

#include <array>
#include <boost/json.hpp>

namespace av::ipc {

namespace {

namespace json = boost::json;

constexpr std::size_t kMaxMessageSize = 16 * 1024 * 1024;

std::string event_kind_to_string(EventKind kind) {
    switch (kind) {
    case EventKind::FileOpen:
        return "file_open";
    case EventKind::FileExec:
        return "file_exec";
    case EventKind::FileModify:
        return "file_modify";
    case EventKind::ProcessStart:
        return "process_start";
    case EventKind::ThreatDetected:
        return "threat_detected";
    case EventKind::ScanProgress:
        return "scan_progress";
    case EventKind::Info:
        return "info";
    }
    return "info";
}

EventKind event_kind_from_string(std::string_view value) {
    if (value == "file_open") {
        return EventKind::FileOpen;
    }
    if (value == "file_exec") {
        return EventKind::FileExec;
    }
    if (value == "file_modify") {
        return EventKind::FileModify;
    }
    if (value == "process_start") {
        return EventKind::ProcessStart;
    }
    if (value == "threat_detected") {
        return EventKind::ThreatDetected;
    }
    if (value == "scan_progress") {
        return EventKind::ScanProgress;
    }
    if (value == "info") {
        return EventKind::Info;
    }
    throw ParseError("decode_event: unknown event kind '" + std::string(value) + "'");
}

std::string command_kind_to_string(CommandKind kind) {
    switch (kind) {
    case CommandKind::Ping:
        return "ping";
    case CommandKind::ScanPath:
        return "scan_path";
    case CommandKind::ScanCancel:
        return "scan_cancel";
    case CommandKind::DeletePath:
        return "delete_path";
    case CommandKind::GetStatus:
        return "get_status";
    case CommandKind::Pause:
        return "pause";
    case CommandKind::Resume:
        return "resume";
    case CommandKind::QuarantinePath:
        return "quarantine_path";
    case CommandKind::QuarantineList:
        return "quarantine_list";
    case CommandKind::QuarantineRestore:
        return "quarantine_restore";
    case CommandKind::QuarantineDelete:
        return "quarantine_delete";
    case CommandKind::ExclusionList:
        return "exclusion_list";
    case CommandKind::ExclusionAdd:
        return "exclusion_add";
    case CommandKind::ExclusionRemove:
        return "exclusion_remove";
    }
    return "ping";
}

CommandKind command_kind_from_string(std::string_view value) {
    if (value == "ping") {
        return CommandKind::Ping;
    }
    if (value == "scan_path") {
        return CommandKind::ScanPath;
    }
    if (value == "scan_cancel") {
        return CommandKind::ScanCancel;
    }
    if (value == "delete_path") {
        return CommandKind::DeletePath;
    }
    if (value == "get_status") {
        return CommandKind::GetStatus;
    }
    if (value == "pause") {
        return CommandKind::Pause;
    }
    if (value == "resume") {
        return CommandKind::Resume;
    }
    if (value == "quarantine_path") {
        return CommandKind::QuarantinePath;
    }
    if (value == "quarantine_list") {
        return CommandKind::QuarantineList;
    }
    if (value == "quarantine_restore") {
        return CommandKind::QuarantineRestore;
    }
    if (value == "quarantine_delete") {
        return CommandKind::QuarantineDelete;
    }
    if (value == "exclusion_list") {
        return CommandKind::ExclusionList;
    }
    if (value == "exclusion_add") {
        return CommandKind::ExclusionAdd;
    }
    if (value == "exclusion_remove") {
        return CommandKind::ExclusionRemove;
    }
    throw ParseError("decode_command: unknown command kind '" + std::string(value) + "'");
}

json::object parse_object(std::string_view text) {
    try {
        json::value value = json::parse(text);
        if (!value.is_object()) {
            throw ParseError("IPC payload is not a JSON object");
        }
        return value.as_object();
    } catch (const std::exception& e) {
        throw ParseError(std::string("IPC JSON parse error: ") + e.what());
    }
}

std::string get_string(const json::object& obj, std::string_view key) {
    auto* field = obj.if_contains(key);
    if (field == nullptr || !field->is_string()) {
        return {};
    }
    return std::string(field->as_string().c_str());
}

std::int64_t get_int(const json::object& obj, std::string_view key) {
    auto* field = obj.if_contains(key);
    if (field == nullptr || !field->is_int64()) {
        return 0;
    }
    return field->as_int64();
}

}

std::string encode_event(const Event& event) {
    json::object obj;
    obj["t"] = "event";
    obj["timestamp_ms"] = event.timestamp_ms;
    obj["kind"] = event_kind_to_string(event.kind);
    obj["path"] = event.path;
    obj["pid"] = event.pid;
    obj["verdict"] = event.verdict;
    obj["threat_name"] = event.threat_name;
    obj["message"] = event.message;
    return json::serialize(obj);
}

std::string encode_command(const Command& command) {
    json::object obj;
    obj["t"] = "command";
    obj["kind"] = command_kind_to_string(command.kind);
    obj["path"] = command.path;
    return json::serialize(obj);
}

std::string encode_reply(const Reply& reply) {
    json::object obj;
    obj["t"] = "reply";
    obj["ok"] = reply.ok;
    obj["detail"] = reply.detail;
    obj["verdict"] = reply.verdict;
    obj["threat_name"] = reply.threat_name;
    json::array items;
    for (const std::string& item : reply.items) {
        items.push_back(json::value(item));
    }
    obj["items"] = std::move(items);
    return json::serialize(obj);
}

MessageType peek_type(std::string_view json_text) {
    json::object obj = parse_object(json_text);
    std::string tag = get_string(obj, "t");
    if (tag == "event") {
        return MessageType::Event;
    }
    if (tag == "command") {
        return MessageType::Command;
    }
    if (tag == "reply") {
        return MessageType::Reply;
    }
    throw ParseError("peek_type: missing or unknown message tag");
}

Event decode_event(std::string_view json_text) {
    json::object obj = parse_object(json_text);
    Event event;
    event.timestamp_ms = get_int(obj, "timestamp_ms");
    event.kind = event_kind_from_string(get_string(obj, "kind"));
    event.path = get_string(obj, "path");
    event.pid = get_int(obj, "pid");
    event.verdict = get_string(obj, "verdict");
    event.threat_name = get_string(obj, "threat_name");
    event.message = get_string(obj, "message");
    return event;
}

Command decode_command(std::string_view json_text) {
    json::object obj = parse_object(json_text);
    Command command;
    command.kind = command_kind_from_string(get_string(obj, "kind"));
    command.path = get_string(obj, "path");
    return command;
}

Reply decode_reply(std::string_view json_text) {
    json::object obj = parse_object(json_text);
    Reply reply;
    auto* ok = obj.if_contains("ok");
    reply.ok = (ok != nullptr && ok->is_bool()) ? ok->as_bool() : false;
    reply.detail = get_string(obj, "detail");
    reply.verdict = get_string(obj, "verdict");
    reply.threat_name = get_string(obj, "threat_name");
    if (auto* items = obj.if_contains("items"); items != nullptr && items->is_array()) {
        for (const json::value& item : items->as_array()) {
            if (item.is_string()) {
                reply.items.emplace_back(item.as_string().c_str());
            }
        }
    }
    return reply;
}

std::string frame(std::string_view payload) {
    std::uint32_t length = static_cast<std::uint32_t>(payload.size());
    std::array<char, 4> header = {
        static_cast<char>((length >> 24) & 0xFF), static_cast<char>((length >> 16) & 0xFF),
        static_cast<char>((length >> 8) & 0xFF), static_cast<char>(length & 0xFF)};
    std::string out(header.begin(), header.end());
    out.append(payload);
    return out;
}

std::optional<std::string> try_unframe(std::string& buffer) {
    if (buffer.size() < 4) {
        return std::nullopt;
    }
    std::uint32_t length =
        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(buffer[0])) << 24) |
        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(buffer[1])) << 16) |
        (static_cast<std::uint32_t>(static_cast<std::uint8_t>(buffer[2])) << 8) |
        static_cast<std::uint32_t>(static_cast<std::uint8_t>(buffer[3]));
    if (length > kMaxMessageSize) {
        throw ParseError("try_unframe: framed message too large");
    }
    if (buffer.size() < 4 + static_cast<std::size_t>(length)) {
        return std::nullopt;
    }
    std::string payload = buffer.substr(4, length);
    buffer.erase(0, 4 + static_cast<std::size_t>(length));
    return payload;
}

}
