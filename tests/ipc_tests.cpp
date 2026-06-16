#include "avcore/error.hpp"
#include "avipc/codec.hpp"

#include <doctest/doctest.h>

using namespace av;
using namespace av::ipc;

TEST_CASE("Event survives a JSON round-trip") {
    Event original;
    original.timestamp_ms = 1700000000000;
    original.kind = EventKind::ThreatDetected;
    original.path = "/tmp/evil.bin";
    original.pid = 4242;
    original.verdict = "infected";
    original.threat_name = "Eicar-Test-File";
    original.message = "blocked on open";

    Event decoded = decode_event(encode_event(original));
    CHECK(decoded.timestamp_ms == original.timestamp_ms);
    CHECK(decoded.kind == EventKind::ThreatDetected);
    CHECK(decoded.path == original.path);
    CHECK(decoded.pid == original.pid);
    CHECK(decoded.threat_name == original.threat_name);
}

TEST_CASE("Command and Reply round-trips") {
    Command command;
    command.kind = CommandKind::ScanPath;
    command.path = "/home/user/Downloads";
    Command dc = decode_command(encode_command(command));
    CHECK(dc.kind == CommandKind::ScanPath);
    CHECK(dc.path == command.path);

    Reply reply{false, "no such file", "error", "", {}};
    Reply dr = decode_reply(encode_reply(reply));
    CHECK_FALSE(dr.ok);
    CHECK(dr.detail == "no such file");
    CHECK(dr.verdict == "error");

    Command del{CommandKind::DeletePath, "/tmp/evil.bin"};
    Command dd = decode_command(encode_command(del));
    CHECK(dd.kind == CommandKind::DeletePath);
    CHECK(dd.path == "/tmp/evil.bin");
}

TEST_CASE("Reply carries a list payload and quarantine commands round-trip") {
    Reply reply;
    reply.ok = true;
    reply.detail = "2 quarantined entries";
    reply.items = {"id1\t/tmp/a\tEicar\t1700000000", "id2\t/tmp/b\tMal\t1700000001"};
    Reply decoded = decode_reply(encode_reply(reply));
    REQUIRE(decoded.items.size() == 2);
    CHECK(decoded.items[0] == "id1\t/tmp/a\tEicar\t1700000000");

    Command command{CommandKind::QuarantineRestore, "id1"};
    Command dc = decode_command(encode_command(command));
    CHECK(dc.kind == CommandKind::QuarantineRestore);
    CHECK(dc.path == "id1");
}

TEST_CASE("Framing recovers messages from a byte stream") {
    std::string stream;
    stream += frame(encode_command(Command{CommandKind::Ping, ""}));
    stream += frame(encode_command(Command{CommandKind::GetStatus, ""}));

    auto first = try_unframe(stream);
    REQUIRE(first.has_value());
    CHECK(decode_command(*first).kind == CommandKind::Ping);

    auto second = try_unframe(stream);
    REQUIRE(second.has_value());
    CHECK(decode_command(*second).kind == CommandKind::GetStatus);

    CHECK_FALSE(try_unframe(stream).has_value());
}

TEST_CASE("peek_type distinguishes message kinds") {
    CHECK(peek_type(encode_event(Event{})) == MessageType::Event);
    CHECK(peek_type(encode_command(Command{})) == MessageType::Command);
    CHECK(peek_type(encode_reply(Reply{})) == MessageType::Reply);
    CHECK_THROWS_AS(peek_type(R"({"no":"tag"})"), ParseError);
}

TEST_CASE("Codec rejects malformed input") {
    SUBCASE("non-JSON payload") {
        CHECK_THROWS_AS(decode_event("not json at all"), ParseError);
    }
    SUBCASE("unknown enum value") {
        CHECK_THROWS_AS(decode_command(R"({"kind":"explode"})"), ParseError);
    }
    SUBCASE("partial frame yields no message") {
        std::string partial = "\x00\x00\x00\x10short";
        CHECK_FALSE(try_unframe(partial).has_value());
    }
}
