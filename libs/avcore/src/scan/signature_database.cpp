#include "avcore/scan/signature_database.hpp"

#include "avcore/error.hpp"
#include "avcore/util/hex.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>

namespace av::scan {

namespace {

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool is_hex_string(const std::string& value) {
    if (value.empty() || value.size() % 2 != 0) {
        return false;
    }
    return std::all_of(value.begin(), value.end(),
                       [](unsigned char c) { return std::isxdigit(c) != 0; });
}

std::string trim(const std::string& value) {
    std::size_t begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return {};
    }
    std::size_t end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

}

SignatureDatabase::SignatureDatabase() : built_(false) {}

void SignatureDatabase::add_hash_signature(const std::string& hex_digest,
                                           const std::string& threat_name) {
    std::string normalized = to_lower(hex_digest);
    if (!is_hex_string(normalized)) {
        throw InvalidArgument("add_hash_signature: invalid hex digest: " + hex_digest);
    }
    hashes_.insert_or_assign(normalized, threat_name);
}

void SignatureDatabase::add_content_signature(std::span<const std::uint8_t> pattern,
                                              const std::string& threat_name) {
    if (built_) {
        throw InvalidArgument("add_content_signature called after build");
    }
    std::uint32_t id = static_cast<std::uint32_t>(pattern_names_.size());
    automaton_.add_pattern(pattern, id);
    pattern_names_.push_back(threat_name);
}

void SignatureDatabase::load_from_file(const std::filesystem::path& path) {
    std::ifstream stream(path);
    if (!stream) {
        throw IoError("SignatureDatabase: cannot open database: " + path.string());
    }

    std::string line;
    std::size_t line_number = 0;
    while (std::getline(stream, line)) {
        ++line_number;
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed.front() == '#') {
            continue;
        }

        std::size_t first = trimmed.find(':');
        std::size_t second = trimmed.find(':', first + 1);
        if (first == std::string::npos || second == std::string::npos) {
            throw ParseError("SignatureDatabase: malformed line " + std::to_string(line_number));
        }
        std::string type = trimmed.substr(0, first);
        std::string value = trimmed.substr(first + 1, second - first - 1);
        std::string name = trimmed.substr(second + 1);

        if (type == "hash") {
            add_hash_signature(value, name);
        } else if (type == "hex") {
            std::string decoded = util::from_hex(value);
            std::span<const std::uint8_t> bytes(
                reinterpret_cast<const std::uint8_t*>(decoded.data()), decoded.size());
            add_content_signature(bytes, name);
        } else {
            throw ParseError("SignatureDatabase: unknown signature type '" + type + "' on line " +
                             std::to_string(line_number));
        }
    }
}

void SignatureDatabase::build() {
    automaton_.build();
    built_ = true;
}

std::optional<std::string> SignatureDatabase::match_hash(const std::string& hex_digest) const {
    auto it = hashes_.find(to_lower(hex_digest));
    if (it == hashes_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<std::string>
SignatureDatabase::match_content(std::span<const std::uint8_t> data) const {
    if (!built_) {
        throw InvalidArgument("SignatureDatabase::match_content called before build");
    }
    if (pattern_names_.empty()) {
        return std::nullopt;
    }
    auto matches = automaton_.find_all(data);
    if (matches.empty()) {
        return std::nullopt;
    }
    return pattern_names_[matches.front().id];
}

}
