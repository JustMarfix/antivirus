#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

/// @file aho_corasick.hpp
/// @brief Aho-Corasick multi-pattern matcher over raw bytes.

namespace av::matching {

/// @brief Multi-pattern byte matcher implementing the Aho-Corasick automaton.
///
/// Patterns are registered with @ref add_pattern, the automaton is finalised
/// with @ref build, and afterwards @ref find_all / @ref contains_any scan input
/// in a single linear pass. The matcher is intended for signature scanning,
/// where every pattern carries a caller-defined identifier.
class AhoCorasick {
  public:
    /// @brief A single pattern occurrence reported by @ref find_all.
    struct Match {
        std::size_t begin; ///< Offset of the first matched byte in the input.
        std::size_t end;   ///< Offset one past the last matched byte.
        std::uint32_t id;  ///< Caller-defined identifier of the pattern.
    };

    /// @brief Construct an empty matcher containing only the root state.
    AhoCorasick();

    /// @brief Register a byte pattern.
    /// @param pattern Non-empty pattern bytes.
    /// @param id Identifier reported when this pattern matches.
    /// @throws av::InvalidArgument if @p pattern is empty.
    /// @throws av::InvalidArgument if called after @ref build.
    void add_pattern(std::span<const std::uint8_t> pattern, std::uint32_t id);

    /// @brief Convenience overload registering a textual pattern.
    /// @param pattern Non-empty pattern characters.
    /// @param id Identifier reported when this pattern matches.
    void add_pattern(std::string_view pattern, std::uint32_t id);

    /// @brief Finalise the automaton by computing failure links.
    ///
    /// Must be called once after all patterns are added and before scanning.
    void build();

    /// @brief Report every pattern occurrence in @p text.
    /// @param text Bytes to scan.
    /// @return All matches in order of their end offset.
    /// @throws av::InvalidArgument if the automaton has not been built.
    std::vector<Match> find_all(std::span<const std::uint8_t> text) const;

    /// @brief Test whether any registered pattern occurs in @p text.
    /// @param text Bytes to scan.
    /// @return True on the first match (scanning stops early), false otherwise.
    /// @throws av::InvalidArgument if the automaton has not been built.
    bool contains_any(std::span<const std::uint8_t> text) const;

    /// @brief Number of registered patterns.
    std::size_t pattern_count() const noexcept { return patterns_.size(); }

  private:
    struct Node {
        std::array<int, 256> next;
        int fail = 0;
        std::vector<std::uint32_t> outputs;
    };

    struct PatternInfo {
        std::size_t length;
        std::uint32_t id;
    };

    std::vector<Node> nodes_;
    std::vector<PatternInfo> patterns_;
    bool built_;
};

}
