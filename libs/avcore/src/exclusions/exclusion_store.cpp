#include "avcore/exclusions/exclusion_store.hpp"

#include "avcore/error.hpp"
#include "avcore/util/path.hpp"

#include <algorithm>
#include <fstream>
#include <system_error>

namespace av::exclusions {

ExclusionStore::ExclusionStore(std::filesystem::path persist_path)
    : persist_path_(std::move(persist_path)) {
    load();
}

std::string ExclusionStore::canonical(const std::string& path) {
    std::error_code ec;
    std::filesystem::path result = std::filesystem::weakly_canonical(path, ec);
    return ec ? path : result.string();
}

bool ExclusionStore::add(const std::string& path) {
    std::string entry = canonical(path);
    if (entry.empty()) {
        throw InvalidArgument("exclusion path is empty");
    }
    if (std::find(entries_.begin(), entries_.end(), entry) != entries_.end()) {
        return false;
    }
    entries_.push_back(std::move(entry));
    std::sort(entries_.begin(), entries_.end());
    save();
    return true;
}

bool ExclusionStore::remove(const std::string& path) {
    std::string entry = canonical(path);
    auto it = std::find(entries_.begin(), entries_.end(), entry);
    if (it == entries_.end()) {
        it = std::find(entries_.begin(), entries_.end(), path);
        if (it == entries_.end()) {
            return false;
        }
    }
    entries_.erase(it);
    save();
    return true;
}

std::vector<std::string> ExclusionStore::list() const {
    return entries_;
}

bool ExclusionStore::is_excluded(std::string_view path) const {
    for (const std::string& entry : entries_) {
        if (util::is_subpath(path, entry)) {
            return true;
        }
    }
    return false;
}

void ExclusionStore::load() {
    if (persist_path_.empty()) {
        return;
    }
    std::error_code ec;
    if (!std::filesystem::exists(persist_path_, ec)) {
        return;
    }
    std::ifstream in(persist_path_);
    if (!in) {
        throw IoError("cannot read exclusion list: " + persist_path_.string());
    }
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) {
            entries_.push_back(line);
        }
    }
    std::sort(entries_.begin(), entries_.end());
    entries_.erase(std::unique(entries_.begin(), entries_.end()), entries_.end());
}

void ExclusionStore::save() const {
    if (persist_path_.empty()) {
        return;
    }
    std::error_code ec;
    std::filesystem::path parent = persist_path_.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
    }
    std::ofstream out(persist_path_, std::ios::trunc);
    if (!out) {
        throw IoError("cannot write exclusion list: " + persist_path_.string());
    }
    for (const std::string& entry : entries_) {
        out << entry << '\n';
    }
    if (!out) {
        throw IoError("failed while writing exclusion list: " + persist_path_.string());
    }
}

}
