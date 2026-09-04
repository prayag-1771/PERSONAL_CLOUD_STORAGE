#include "pcs/daemon.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

using namespace std;

namespace pcs {

bool daemonize(const string& log_path, const string& pid_path, string& error) {
#ifdef _WIN32
    (void)log_path;
    (void)pid_path;
    error =
        "detaching is not supported on Windows. Run it as a scheduled task "
        "set to start at logon, or install it as a service with a wrapper "
        "such as NSSM.";
    return false;
#else
    const pid_t child = fork();
    if (child < 0) {
        error = "cannot fork";
        return false;
    }
    if (child > 0) {
        // The parent has nothing left to do, and must not run the caller's
        // remaining work as well.
        _exit(0);
    }

    // A new session, so the process is not killed when the terminal closes
    // and has no controlling terminal to be stopped by.
    if (setsid() < 0) {
        error = "cannot start a new session";
        return false;
    }

    // Forking a second time makes the process unable to reacquire a
    // terminal, which is what keeps it detached for good.
    const pid_t grandchild = fork();
    if (grandchild < 0) {
        error = "cannot fork";
        return false;
    }
    if (grandchild > 0) _exit(0);

    umask(0027);

    if (!pid_path.empty()) {
        ofstream out(pid_path, ios::trunc);
        if (out) out << getpid() << "\n";
    }

    const int null_fd = open("/dev/null", O_RDONLY);
    if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        if (null_fd > STDERR_FILENO) close(null_fd);
    }

    const string target = log_path.empty() ? "/dev/null" : log_path;
    const int log_fd = open(target.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0640);
    if (log_fd < 0) {
        error = "cannot open the log file " + target;
        return false;
    }
    dup2(log_fd, STDOUT_FILENO);
    dup2(log_fd, STDERR_FILENO);
    if (log_fd > STDERR_FILENO) close(log_fd);

    // Writing to a file rather than a terminal switches stdout to full
    // buffering, so output would sit unwritten while the process waits for
    // connections. A log nobody can read until the process exits is no use,
    // so ask for line buffering back.
    setvbuf(stdout, nullptr, _IOLBF, 0);
    setvbuf(stderr, nullptr, _IOLBF, 0);
    cout.setf(ios::unitbuf);

    return true;
#endif
}

string systemd_unit(const string& description, const string& exec_line,
                    const string& working_dir) {
    string unit;
    unit += "[Unit]\n";
    unit += "Description=" + description + "\n";
    unit += "After=network-online.target\n";
    unit += "Wants=network-online.target\n";
    unit += "\n";
    unit += "[Service]\n";
    unit += "Type=simple\n";
    unit += "ExecStart=" + exec_line + "\n";
    if (!working_dir.empty()) unit += "WorkingDirectory=" + working_dir + "\n";
    unit += "Restart=on-failure\n";
    unit += "RestartSec=5\n";
    unit += "\n";
    unit += "[Install]\n";
    unit += "WantedBy=default.target\n";
    return unit;
}

}  // namespace pcs
