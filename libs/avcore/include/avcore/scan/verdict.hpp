#pragma once

#include <string>

/// @file verdict.hpp
/// @brief Result types produced by the scanning engine.

namespace av::scan {

/// @brief Overall classification of a scanned object.
enum class Verdict {
    Clean,    ///< No signature matched.
    Infected, ///< At least one signature matched.
    Error     ///< The object could not be scanned.
};

/// @brief Human-readable name for a verdict.
/// @param verdict Verdict to describe.
/// @return Stable lowercase label ("clean", "infected", "error").
std::string to_string(Verdict verdict);

/// @brief Outcome of scanning a single object.
struct ScanResult {
    Verdict verdict = Verdict::Clean; ///< Overall classification.
    std::string threat_name;          ///< Threat name when @ref verdict is Infected.
    std::string detail;               ///< Extra context (matched rule, error text).

    /// @brief Convenience predicate.
    /// @return True if @ref verdict is Verdict::Infected.
    bool infected() const noexcept { return verdict == Verdict::Infected; }
};

}
