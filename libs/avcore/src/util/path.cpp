#include "avcore/util/path.hpp"

namespace av::util {

bool is_subpath(std::string_view path, std::string_view prefix) {
    while (prefix.size() > 1 && prefix.back() == '/') {
        prefix.remove_suffix(1);
    }
    if (prefix.empty() || path.size() < prefix.size()) {
        return false;
    }
    if (path.substr(0, prefix.size()) != prefix) {
        return false;
    }
    return path.size() == prefix.size() || path[prefix.size()] == '/';
}

}
