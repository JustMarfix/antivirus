#include "avcore/quarantine/quarantine.hpp"

#include "avcore/error.hpp"
#include "avcore/hashing/sha256.hpp"
#include "avcore/util/hex.hpp"

#include <chrono>
#include <fstream>
#include <span>

namespace av::quarantine {

namespace fs = std::filesystem;

namespace {

std::int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string make_id(const std::string& seed) {
    std::span<const std::uint8_t> bytes(reinterpret_cast<const std::uint8_t*>(seed.data()),
                                        seed.size());
    return av::hashing::Sha256::hash_hex(bytes).substr(0, 16);
}

void set_owner_only(const fs::path& path) {
    std::error_code ec;
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace,
                    ec);
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

Quarantine::Quarantine(fs::path store_dir) : store_dir_(std::move(store_dir)) {
    std::error_code ec;
    fs::create_directories(store_dir_, ec);
    if (ec) {
        throw IoError("Quarantine: cannot create store '" + store_dir_.string() +
                      "': " + ec.message());
    }
    fs::permissions(store_dir_, fs::perms::owner_all, fs::perm_options::replace, ec);
}

fs::path Quarantine::data_path(const std::string& id) const {
    return store_dir_ / (id + ".quar");
}

fs::path Quarantine::meta_path(const std::string& id) const {
    return store_dir_ / (id + ".meta");
}

QuarantineEntry Quarantine::quarantine_file(const fs::path& path, const std::string& threat_name) {
    std::error_code ec;
    if (!fs::is_regular_file(path, ec) || ec) {
        throw IoError("quarantine_file: not a regular file: " + path.string());
    }
    fs::path absolute = fs::absolute(path, ec);
    if (ec) {
        absolute = path;
    }

    std::int64_t timestamp = now_seconds();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                  std::chrono::system_clock::now().time_since_epoch())
                  .count();
    std::string id = make_id(absolute.string() + "|" + std::to_string(ns));

    fs::perms original_perms = fs::status(absolute, ec).permissions();
    std::uint32_t mode_bits = static_cast<std::uint32_t>(original_perms & fs::perms::mask);

    fs::path data = data_path(id);
    fs::rename(absolute, data, ec);
    if (ec) {
        std::error_code copy_ec;
        fs::copy_file(absolute, data, fs::copy_options::overwrite_existing, copy_ec);
        if (copy_ec) {
            throw IoError("quarantine_file: cannot move '" + absolute.string() +
                          "': " + copy_ec.message());
        }
        std::error_code rm_ec;
        fs::remove(absolute, rm_ec);
        if (rm_ec) {
            fs::remove(data, copy_ec);
            throw IoError("quarantine_file: cannot remove original '" + absolute.string() +
                          "': " + rm_ec.message());
        }
    }
    set_owner_only(data);

    std::ofstream meta(meta_path(id));
    if (!meta) {
        throw IoError("quarantine_file: cannot write metadata for " + id);
    }
    meta << "original_path=" << absolute.string() << '\n'
         << "threat_name=" << threat_name << '\n'
         << "quarantined_at=" << timestamp << '\n'
         << "original_mode=" << mode_bits << '\n';
    meta.close();
    set_owner_only(meta_path(id));

    return QuarantineEntry{id, absolute.string(), threat_name, timestamp};
}

QuarantineEntry Quarantine::read_meta(const fs::path& meta) const {
    std::ifstream stream(meta);
    if (!stream) {
        throw IoError("quarantine: cannot read metadata: " + meta.string());
    }
    QuarantineEntry entry;
    entry.id = meta.stem().string();
    std::string line;
    while (std::getline(stream, line)) {
        std::size_t eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        std::string key = trim(line.substr(0, eq));
        std::string value = line.substr(eq + 1);
        if (key == "original_path") {
            entry.original_path = value;
        } else if (key == "threat_name") {
            entry.threat_name = value;
        } else if (key == "quarantined_at") {
            entry.quarantined_at = std::stoll(trim(value));
        }
    }
    return entry;
}

std::vector<QuarantineEntry> Quarantine::list() const {
    std::vector<QuarantineEntry> entries;
    std::error_code ec;
    for (auto it = fs::directory_iterator(store_dir_, ec); !ec && it != fs::directory_iterator();
         it.increment(ec)) {
        if (it->path().extension() == ".meta") {
            entries.push_back(read_meta(it->path()));
        }
    }
    return entries;
}

QuarantineEntry Quarantine::get(const std::string& id) const {
    std::error_code ec;
    if (!fs::exists(meta_path(id), ec)) {
        throw InvalidArgument("quarantine: unknown entry: " + id);
    }
    return read_meta(meta_path(id));
}

void Quarantine::restore(const std::string& id) {
    QuarantineEntry entry = get(id);
    fs::path target = entry.original_path;
    std::error_code ec;

    if (fs::exists(target, ec)) {
        throw IoError("quarantine restore: target already exists: " + target.string());
    }
    if (target.has_parent_path()) {
        fs::create_directories(target.parent_path(), ec);
    }

    fs::rename(data_path(id), target, ec);
    if (ec) {
        std::error_code copy_ec;
        fs::copy_file(data_path(id), target, copy_ec);
        if (copy_ec) {
            throw IoError("quarantine restore: cannot move file back: " + copy_ec.message());
        }
        fs::remove(data_path(id), copy_ec);
    }

    std::ifstream meta(meta_path(id));
    std::string line;
    while (std::getline(meta, line)) {
        std::size_t eq = line.find('=');
        if (eq != std::string::npos && trim(line.substr(0, eq)) == "original_mode") {
            std::uint32_t bits = static_cast<std::uint32_t>(std::stoul(trim(line.substr(eq + 1))));
            fs::permissions(target, static_cast<fs::perms>(bits), fs::perm_options::replace, ec);
        }
    }
    meta.close();
    fs::remove(meta_path(id), ec);
}

void Quarantine::remove(const std::string& id) {
    std::error_code ec;
    if (!fs::exists(meta_path(id), ec)) {
        throw InvalidArgument("quarantine: unknown entry: " + id);
    }
    fs::remove(data_path(id), ec);
    fs::remove(meta_path(id), ec);
}

}
