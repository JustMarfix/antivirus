#include "desktop_notifier.hpp"

#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace av::client {

void DesktopNotifier::notify(const std::string& summary, const std::string& body,
                             bool critical) const noexcept {
    const char* bus = std::getenv("DBUS_SESSION_BUS_ADDRESS");
    if (bus == nullptr || bus[0] == '\0') {
        return;
    }

    std::string urgency = critical ? "critical" : "normal";
    std::vector<char*> argv;
    std::string program = "notify-send";
    std::string flag_app = "-a";
    std::string app_name = "Linux Antivirus";
    std::string flag_urgency = "-u";
    std::string icon_flag = "-i";
    std::string icon = "security-high";
    std::string summary_copy = summary;
    std::string body_copy = body;
    argv.push_back(program.data());
    argv.push_back(flag_app.data());
    argv.push_back(app_name.data());
    argv.push_back(flag_urgency.data());
    argv.push_back(urgency.data());
    argv.push_back(icon_flag.data());
    argv.push_back(icon.data());
    argv.push_back(summary_copy.data());
    argv.push_back(body_copy.data());
    argv.push_back(nullptr);

    pid_t pid = ::fork();
    if (pid < 0) {
        return;
    }
    if (pid == 0) {
        int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDOUT_FILENO);
            ::dup2(devnull, STDERR_FILENO);
        }
        ::execvp(argv[0], argv.data());
        ::_exit(127);
    }
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            break;
        }
    }
}

}
