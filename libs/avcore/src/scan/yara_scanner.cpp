#include "avcore/scan/yara_scanner.hpp"

#include "avcore/error.hpp"
#include "avcore/util/file.hpp"

#include <algorithm>
#include <cstdio>
#include <memory>
#include <system_error>
#include <vector>
#include <yara.h>

namespace av::scan {

namespace {

// Collects the first matching rule name during a scan.
struct MatchState {
    std::optional<std::string> name;
};

int scan_callback(YR_SCAN_CONTEXT* /*context*/, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* state = static_cast<MatchState*>(user_data);
        const auto* rule = static_cast<const YR_RULE*>(message_data);
        state->name = std::string(rule->identifier);
        return CALLBACK_ABORT;
    }
    return CALLBACK_CONTINUE;
}

}

YaraScanner::YaraScanner() {
    if (yr_initialize() != ERROR_SUCCESS) {
        throw ScanError("YARA: failed to initialise");
    }
    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        yr_finalize();
        throw ScanError("YARA: failed to create compiler");
    }
    compiler_ = compiler;
}

YaraScanner::~YaraScanner() {
    if (rules_ != nullptr) {
        yr_rules_destroy(static_cast<YR_RULES*>(rules_));
    }
    if (compiler_ != nullptr) {
        yr_compiler_destroy(static_cast<YR_COMPILER*>(compiler_));
    }
    yr_finalize();
}

void YaraScanner::add_rules_string(const std::string& rules) {
    if (compiler_ == nullptr) {
        throw InvalidArgument("YaraScanner: rules added after compile()");
    }
    int errors =
        yr_compiler_add_string(static_cast<YR_COMPILER*>(compiler_), rules.c_str(), nullptr);
    if (errors > 0) {
        throw ScanError("YARA: " + std::to_string(errors) + " rule compilation error(s)");
    }
}

void YaraScanner::add_rules_file(const std::filesystem::path& path) {
    if (compiler_ == nullptr) {
        throw InvalidArgument("YaraScanner: rules added after compile()");
    }

    std::unique_ptr<std::FILE, int (*)(std::FILE*)> file(std::fopen(path.c_str(), "r"),
                                                         &std::fclose);
    if (!file) {
        throw IoError("YaraScanner: cannot open rules file: " + path.string());
    }
    int errors = yr_compiler_add_file(static_cast<YR_COMPILER*>(compiler_), file.get(), nullptr,
                                      path.string().c_str());
    if (errors > 0) {
        throw ScanError("YARA: " + std::to_string(errors) + " rule compilation error(s) in " +
                        path.string());
    }
}

std::size_t YaraScanner::add_rules_path(const std::filesystem::path& path) {
    if (compiler_ == nullptr) {
        throw InvalidArgument("YaraScanner: rules added after compile()");
    }
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        throw IoError("YaraScanner: rules path does not exist: " + path.string());
    }
    if (!std::filesystem::is_directory(path, ec)) {
        add_rules_file(path);
        return 1;
    }

    std::vector<std::filesystem::path> files;
    for (const std::filesystem::directory_entry& entry :
         std::filesystem::recursive_directory_iterator(path)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        std::string ext = entry.path().extension().string();
        if (ext == ".yar" || ext == ".yara") {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());
    for (const std::filesystem::path& file : files) {
        add_rules_file(file);
    }
    return files.size();
}

void YaraScanner::compile() {
    YR_RULES* rules = nullptr;
    if (yr_compiler_get_rules(static_cast<YR_COMPILER*>(compiler_), &rules) != ERROR_SUCCESS) {
        throw ScanError("YARA: failed to build rules");
    }
    rules_ = rules;

    yr_compiler_destroy(static_cast<YR_COMPILER*>(compiler_));
    compiler_ = nullptr;
}

std::optional<std::string> YaraScanner::scan_buffer(std::span<const std::uint8_t> data) const {
    if (rules_ == nullptr) {
        throw InvalidArgument("YaraScanner::scan_buffer called before compile()");
    }
    MatchState state;
    int rc = yr_rules_scan_mem(static_cast<YR_RULES*>(rules_), data.data(), data.size(), 0,
                               scan_callback, &state, 0);
    if (rc != ERROR_SUCCESS) {
        throw ScanError("YARA: scan failed with code " + std::to_string(rc));
    }
    return state.name;
}

std::optional<std::string> YaraScanner::scan_file(const std::filesystem::path& path) const {
    std::vector<std::uint8_t> data = util::read_file(path);
    return scan_buffer(data);
}

}
