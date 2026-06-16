#include "avcore/analysis/elf_analyzer.hpp"
#include "avcore/error.hpp"
#include "avcore/scan/file_scanner.hpp"
#include "avcore/scan/signature_database.hpp"

#ifdef AV_HAVE_YARA
#include "avcore/scan/yara_scanner.hpp"
#endif

#include <filesystem>
#include <iostream>
#include <span>
#include <string>
#include <vector>

/// @file main.cpp
/// @brief Command-line on-demand scanner exercising the avcore engine.

namespace {

namespace fs = std::filesystem;

void print_usage(const char* program) {
    std::cerr << "Usage: " << program << " [--db <signatures>] [--yara <rules>] [--elf] <path>...\n"
              << "  --db <file>    Load signatures from <file> (type:value:name per line).\n"
              << "  --yara <path>  Load YARA rules from a file or a directory of\n"
              << "                 *.yar/*.yara files, recursively (YARA-enabled build).\n"
              << "  --elf          Also print ELF analysis for scanned files.\n";
}

void report(const fs::path& path, const av::scan::ScanResult& result, bool show_elf) {
    std::cout << av::scan::to_string(result.verdict) << '\t' << path.string();
    if (result.infected()) {
        std::cout << "\t" << result.threat_name;
    } else if (result.verdict == av::scan::Verdict::Error) {
        std::cout << "\t" << result.detail;
    }
    std::cout << '\n';

    if (show_elf && result.verdict != av::scan::Verdict::Error) {
        try {
            av::analysis::ElfInfo info = av::analysis::analyze_elf_file(path);
            if (info.is_elf) {
                std::cout << "  elf: " << info.machine << (info.is_64bit ? "/64" : "/32")
                          << " sections=" << info.section_count
                          << " w^x-violation=" << (info.has_write_exec_segment ? "yes" : "no")
                          << '\n';
            }
        } catch (const av::AvException& e) {
            std::cout << "  elf: analysis failed: " << e.what() << '\n';
        }
    }
}

std::size_t scan_path(const fs::path& path, const av::scan::FileScanner& scanner, bool show_elf) {
    std::size_t infected = 0;
    std::error_code ec;
    if (fs::is_directory(path, ec)) {
        for (auto it = fs::recursive_directory_iterator(
                 path, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) {
                break;
            }
            if (it->is_regular_file(ec)) {
                av::scan::ScanResult result = scanner.scan_file(it->path());
                report(it->path(), result, show_elf);
                infected += result.infected() ? 1 : 0;
            }
        }
    } else {
        av::scan::ScanResult result = scanner.scan_file(path);
        report(path, result, show_elf);
        infected += result.infected() ? 1 : 0;
    }
    return infected;
}

}

int main(int argc, char** argv) {
    try {
        std::vector<std::string> args(argv + 1, argv + argc);
        fs::path db_path;
        fs::path yara_path;
        bool show_elf = false;
        std::vector<fs::path> targets;

        for (std::size_t i = 0; i < args.size(); ++i) {
            if (args[i] == "--db" && i + 1 < args.size()) {
                db_path = args[++i];
            } else if (args[i] == "--yara" && i + 1 < args.size()) {
                yara_path = args[++i];
            } else if (args[i] == "--elf") {
                show_elf = true;
            } else if (args[i] == "--help" || args[i] == "-h") {
                print_usage(argv[0]);
                return 0;
            } else {
                targets.emplace_back(args[i]);
            }
        }

        if (targets.empty()) {
            print_usage(argv[0]);
            return 2;
        }

        av::scan::SignatureDatabase db;
        if (!db_path.empty()) {
            db.load_from_file(db_path);
        }
        db.build();

#ifdef AV_HAVE_YARA
        av::scan::YaraScanner yara;
        bool have_yara = !yara_path.empty();
        if (have_yara) {
            yara.add_rules_path(yara_path);
            yara.compile();
        }
        av::scan::FileScanner scanner(db, 64 * 1024 * 1024, have_yara ? &yara : nullptr);
#else
        if (!yara_path.empty()) {
            std::cerr << "avscan: built without YARA support (-DAV_ENABLE_YARA=ON)\n";
            return 2;
        }
        av::scan::FileScanner scanner(db);
#endif

        std::size_t infected = 0;
        for (const fs::path& target : targets) {
            infected += scan_path(target, scanner, show_elf);
        }

        std::cout << "---\n" << infected << " infected object(s) found\n";
        return infected == 0 ? 0 : 1;
    } catch (const av::AvException& e) {
        std::cerr << "error: " << e.what() << '\n';
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << '\n';
        return 3;
    }
}
