#include "avcore/util/file.hpp"

#include "avcore/error.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <unistd.h>

namespace av::util {

std::vector<std::uint8_t> read_file(const std::filesystem::path& path, std::size_t max_bytes) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec) {
        throw IoError("read_file: not a regular file: " + path.string());
    }

    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw IoError("read_file: cannot open file: " + path.string());
    }

    std::vector<std::uint8_t> data;
    std::array<char, 64 * 1024> chunk{};
    while (stream && data.size() < max_bytes) {
        std::size_t want = std::min(chunk.size(), max_bytes - data.size());
        stream.read(chunk.data(), static_cast<std::streamsize>(want));
        std::streamsize got = stream.gcount();
        if (got <= 0) {
            break;
        }
        data.insert(data.end(), reinterpret_cast<std::uint8_t*>(chunk.data()),
                    reinterpret_cast<std::uint8_t*>(chunk.data()) + got);
    }

    if (stream.bad()) {
        throw IoError("read_file: read error on file: " + path.string());
    }
    return data;
}

std::vector<std::uint8_t> read_fd(int fd, std::size_t max_bytes) {
    std::vector<std::uint8_t> data;
    std::array<char, 64 * 1024> chunk{};
    off_t offset = 0;
    while (data.size() < max_bytes) {
        std::size_t want = std::min(chunk.size(), max_bytes - data.size());
        ssize_t got = ::pread(fd, chunk.data(), want, offset);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw IoError(std::string("read_fd: pread failed: ") + std::strerror(errno));
        }
        if (got == 0) {
            break;
        }
        data.insert(data.end(), reinterpret_cast<std::uint8_t*>(chunk.data()),
                    reinterpret_cast<std::uint8_t*>(chunk.data()) + got);
        offset += got;
    }
    return data;
}

}
