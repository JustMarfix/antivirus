#pragma once

#include <stdexcept>
#include <string>

/// @file error.hpp
/// @brief Exception hierarchy used across the antivirus core.
///
/// Every recoverable failure in the project is reported by throwing one of the
/// types declared here (or a standard-library exception), satisfying the
/// requirement that all error reporting goes through the exception mechanism.

namespace av {

/// @brief Base class for every exception raised by the antivirus core.
class AvException : public std::runtime_error {
  public:
    /// @brief Construct the exception with a human-readable message.
    /// @param message Description of the failure.
    explicit AvException(const std::string& message) : std::runtime_error(message) {}
};

/// @brief Raised when an input/output operation on a file or socket fails.
class IoError : public AvException {
  public:
    /// @copydoc AvException::AvException
    explicit IoError(const std::string& message) : AvException(message) {}
};

/// @brief Raised when parsing structured data (config, ELF, protocol) fails.
class ParseError : public AvException {
  public:
    /// @copydoc AvException::AvException
    explicit ParseError(const std::string& message) : AvException(message) {}
};

/// @brief Raised when the scanning engine cannot complete an operation.
class ScanError : public AvException {
  public:
    /// @copydoc AvException::AvException
    explicit ScanError(const std::string& message) : AvException(message) {}
};

/// @brief Raised when a function receives an argument that violates its contract.
class InvalidArgument : public AvException {
  public:
    /// @copydoc AvException::AvException
    explicit InvalidArgument(const std::string& message) : AvException(message) {}
};

}
