#pragma once

#include "avipc/message.hpp"

#include <optional>
#include <string>
#include <string_view>

/// @file codec.hpp
/// @brief JSON (de)serialisation and length-prefixed framing for IPC messages.
///
/// Each message is serialised to a compact JSON object. On the wire a message
/// is prefixed with its length as a 4-byte big-endian integer so that a stream
/// reader can recover individual messages.

namespace av::ipc {

/// @brief Discriminator identifying which message a JSON payload carries.
enum class MessageType {
    Event,   ///< An asynchronous @ref Event.
    Command, ///< A client @ref Command.
    Reply    ///< A @ref Reply to a command.
};

/// @brief Determine the message type of a JSON payload from its tag.
/// @param json JSON object text.
/// @return The decoded message type.
/// @throws av::ParseError if the tag is missing or unknown.
MessageType peek_type(std::string_view json);

/// @brief Serialise an event to its JSON representation.
/// @param event Event to encode.
/// @return Compact JSON object text.
std::string encode_event(const Event& event);

/// @brief Serialise a command to its JSON representation.
/// @param command Command to encode.
/// @return Compact JSON object text.
std::string encode_command(const Command& command);

/// @brief Serialise a reply to its JSON representation.
/// @param reply Reply to encode.
/// @return Compact JSON object text.
std::string encode_reply(const Reply& reply);

/// @brief Parse an event from JSON.
/// @param json JSON object text.
/// @return The decoded event.
/// @throws av::ParseError on malformed input.
Event decode_event(std::string_view json);

/// @brief Parse a command from JSON.
/// @param json JSON object text.
/// @return The decoded command.
/// @throws av::ParseError on malformed input.
Command decode_command(std::string_view json);

/// @brief Parse a reply from JSON.
/// @param json JSON object text.
/// @return The decoded reply.
/// @throws av::ParseError on malformed input.
Reply decode_reply(std::string_view json);

/// @brief Wrap a payload with a 4-byte big-endian length prefix.
/// @param payload Serialised message text.
/// @return Framed bytes ready to write to a stream.
std::string frame(std::string_view payload);

/// @brief Extract one framed message from the front of a stream buffer.
/// @param buffer In/out buffer holding received bytes; consumed bytes are
///        erased from the front when a full message is available.
/// @return The unframed payload, or std::nullopt if @p buffer holds no complete
///         message yet.
/// @throws av::ParseError if the framed length is implausibly large.
std::optional<std::string> try_unframe(std::string& buffer);

}
