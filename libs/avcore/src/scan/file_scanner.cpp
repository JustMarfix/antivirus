#include "avcore/scan/file_scanner.hpp"

#include "avcore/error.hpp"
#include "avcore/hashing/md5.hpp"
#include "avcore/hashing/sha1.hpp"
#include "avcore/hashing/sha256.hpp"
#include "avcore/util/file.hpp"

#ifdef AV_HAVE_YARA
#include "avcore/scan/yara_scanner.hpp"
#endif

#include <array>
#include <utility>

namespace av::scan {

FileScanner::FileScanner(const SignatureDatabase& database, std::size_t max_scan_bytes,
                         const YaraScanner* yara)
    : database_(database), max_scan_bytes_(max_scan_bytes), yara_(yara) {}

ScanResult FileScanner::scan_buffer(std::span<const std::uint8_t> data,
                                    const std::string& object_name) const {
    std::array<std::pair<const char*, std::string>, 3> digests = {
        std::pair{"md5", hashing::Md5::hash_hex(data)},
        std::pair{"sha1", hashing::Sha1::hash_hex(data)},
        std::pair{"sha256", hashing::Sha256::hash_hex(data)}};
    for (const auto& [algorithm, digest] : digests) {
        if (auto threat = database_.match_hash(digest)) {
            return ScanResult{Verdict::Infected, *threat, std::string(algorithm) + ":" + digest};
        }
    }
    if (auto threat = database_.match_content(data)) {
        return ScanResult{Verdict::Infected, *threat, "content-signature"};
    }
#ifdef AV_HAVE_YARA
    if (yara_ != nullptr && yara_->ready()) {
        if (auto rule = yara_->scan_buffer(data)) {
            return ScanResult{Verdict::Infected, *rule, "yara-rule"};
        }
    }
#endif
    return ScanResult{Verdict::Clean, {}, object_name};
}

ScanResult FileScanner::scan_file(const std::filesystem::path& path) const {
    try {
        std::vector<std::uint8_t> data = util::read_file(path, max_scan_bytes_);
        ScanResult result = scan_buffer(data, path.string());
        return result;
    } catch (const AvException& e) {
        return ScanResult{Verdict::Error, {}, e.what()};
    }
}

ScanResult FileScanner::scan_fd(int fd, const std::string& object_name) const {
    try {
        std::vector<std::uint8_t> data = util::read_fd(fd, max_scan_bytes_);
        return scan_buffer(data, object_name);
    } catch (const AvException& e) {
        return ScanResult{Verdict::Error, {}, e.what()};
    }
}

}
