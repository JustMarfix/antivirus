#include "avcore/util/unique_fd.hpp"

#include <unistd.h>

namespace av::util {

void UniqueFd::reset() noexcept {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

}
