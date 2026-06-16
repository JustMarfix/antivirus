#include "avcore/matching/aho_corasick.hpp"

#include "avcore/error.hpp"

#include <deque>

namespace av::matching {

namespace {

AhoCorasick::Match make_match(std::size_t end_offset, std::size_t length, std::uint32_t id) {
    std::size_t end = end_offset + 1;
    return AhoCorasick::Match{end - length, end, id};
}

}

AhoCorasick::AhoCorasick() : built_(false) {
    Node root;
    root.next.fill(-1);
    nodes_.push_back(root);
}

void AhoCorasick::add_pattern(std::span<const std::uint8_t> pattern, std::uint32_t id) {
    if (built_) {
        throw InvalidArgument("AhoCorasick::add_pattern called after build");
    }
    if (pattern.empty()) {
        throw InvalidArgument("AhoCorasick::add_pattern: pattern must not be empty");
    }

    int current = 0;
    for (std::uint8_t byte : pattern) {
        if (nodes_[static_cast<std::size_t>(current)].next[byte] == -1) {
            Node child;
            child.next.fill(-1);
            nodes_.push_back(child);
            nodes_[static_cast<std::size_t>(current)].next[byte] =
                static_cast<int>(nodes_.size() - 1);
        }
        current = nodes_[static_cast<std::size_t>(current)].next[byte];
    }

    std::uint32_t pattern_index = static_cast<std::uint32_t>(patterns_.size());
    patterns_.push_back(PatternInfo{pattern.size(), id});
    nodes_[static_cast<std::size_t>(current)].outputs.push_back(pattern_index);
}

void AhoCorasick::add_pattern(std::string_view pattern, std::uint32_t id) {
    std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t*>(pattern.data()),
                                        pattern.size());
    add_pattern(bytes, id);
}

void AhoCorasick::build() {
    std::deque<int> queue;
    Node& root = nodes_[0];
    for (int c = 0; c < 256; ++c) {
        int child = root.next[static_cast<std::size_t>(c)];
        if (child == -1) {
            root.next[static_cast<std::size_t>(c)] = 0;
        } else {
            nodes_[static_cast<std::size_t>(child)].fail = 0;
            queue.push_back(child);
        }
    }

    while (!queue.empty()) {
        int u = queue.front();
        queue.pop_front();
        for (int c = 0; c < 256; ++c) {
            int v = nodes_[static_cast<std::size_t>(u)].next[static_cast<std::size_t>(c)];
            int fail = nodes_[static_cast<std::size_t>(u)].fail;
            if (v == -1) {
                nodes_[static_cast<std::size_t>(u)].next[static_cast<std::size_t>(c)] =
                    nodes_[static_cast<std::size_t>(fail)].next[static_cast<std::size_t>(c)];
                continue;
            }
            nodes_[static_cast<std::size_t>(v)].fail =
                nodes_[static_cast<std::size_t>(fail)].next[static_cast<std::size_t>(c)];
            int vfail = nodes_[static_cast<std::size_t>(v)].fail;
            const std::vector<std::uint32_t>& inherited =
                nodes_[static_cast<std::size_t>(vfail)].outputs;
            std::vector<std::uint32_t>& outputs = nodes_[static_cast<std::size_t>(v)].outputs;
            outputs.insert(outputs.end(), inherited.begin(), inherited.end());
            queue.push_back(v);
        }
    }

    built_ = true;
}

std::vector<AhoCorasick::Match> AhoCorasick::find_all(std::span<const std::uint8_t> text) const {
    if (!built_) {
        throw InvalidArgument("AhoCorasick::find_all called before build");
    }
    std::vector<Match> matches;
    int state = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
        state = nodes_[static_cast<std::size_t>(state)].next[text[i]];
        for (std::uint32_t idx : nodes_[static_cast<std::size_t>(state)].outputs) {
            const PatternInfo& info = patterns_[idx];
            matches.push_back(make_match(i, info.length, info.id));
        }
    }
    return matches;
}

bool AhoCorasick::contains_any(std::span<const std::uint8_t> text) const {
    if (!built_) {
        throw InvalidArgument("AhoCorasick::contains_any called before build");
    }
    int state = 0;
    for (std::uint8_t byte : text) {
        state = nodes_[static_cast<std::size_t>(state)].next[byte];
        if (!nodes_[static_cast<std::size_t>(state)].outputs.empty()) {
            return true;
        }
    }
    return false;
}

}
