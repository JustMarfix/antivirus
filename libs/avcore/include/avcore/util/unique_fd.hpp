#pragma once

#include <utility>

/// @file unique_fd.hpp
/// @brief RAII owner for a POSIX file descriptor.

namespace av::util {

/// @brief Move-only owner that closes its file descriptor on destruction.
///
/// Used to manage the raw descriptors returned by Linux system calls
/// (fanotify, sockets, opened files) without manual resource handling.
class UniqueFd {
  public:
    /// @brief Construct an empty owner that holds no descriptor.
    UniqueFd() noexcept = default;

    /// @brief Take ownership of an existing descriptor.
    /// @param fd Descriptor to own, or a negative value for "none".
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    /// @brief Take ownership from another owner, leaving it empty.
    /// @param other Source owner.
    UniqueFd(UniqueFd&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }

    /// @brief Move-assign, closing any currently held descriptor first.
    /// @param other Source owner.
    /// @return Reference to this owner.
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    /// @brief Close the held descriptor, if any.
    ~UniqueFd() { reset(); }

    /// @brief Whether a descriptor is currently owned.
    /// @return True if the held descriptor is valid (non-negative).
    bool valid() const noexcept { return fd_ >= 0; }

    /// @brief Access the raw descriptor without giving up ownership.
    /// @return The held descriptor, or a negative value if empty.
    int get() const noexcept { return fd_; }

    /// @brief Relinquish ownership of the descriptor.
    /// @return The previously held descriptor; the owner becomes empty.
    int release() noexcept { return std::exchange(fd_, -1); }

    /// @brief Close the held descriptor and become empty.
    void reset() noexcept;

  private:
    int fd_ = -1;
};

}
