#pragma once

#include <string>

// Detaching from the terminal, so a server or a watcher survives the window
// that started it being closed.
namespace pcs {

// Forks into the background, redirects output to `log_path`, and writes the
// new process id to `pid_path` when it is not empty. Returns true in the
// detached child; the parent exits from inside this call.
//
// Windows has no fork, so there it reports what to use instead rather than
// pretending to have worked.
bool daemonize(const std::string& log_path, const std::string& pid_path,
               std::string& error);

// A systemd unit for running the given command at boot, printed for the user
// to install. Generating it beats describing it in prose that has to be
// retyped correctly.
std::string systemd_unit(const std::string& description,
                         const std::string& exec_line,
                         const std::string& working_dir);

}  // namespace pcs
