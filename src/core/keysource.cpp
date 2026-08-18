#include "pcs/keysource.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>

#ifdef _WIN32
#include <io.h>
#include <cstdio>
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace pcs {
namespace {

constexpr char kEnvVar[] = "PCS_PASSPHRASE";

void strip_trailing_newline(std::string& s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
}

// True when stdin is a terminal, i.e. there is somebody there to type.
bool stdin_is_tty() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(STDIN_FILENO) != 0;
#endif
}

bool read_keyfile(const std::string& path, std::string& out, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "cannot read key file: " + path;
        return false;
    }
    std::string line;
    std::getline(in, line);
    strip_trailing_newline(line);
    if (line.empty()) {
        error = "key file is empty: " + path;
        return false;
    }
    out = line;
    return true;
}

}  // namespace

bool read_hidden_line(const std::string& prompt, std::string& out) {
    std::cout << prompt << std::flush;

#ifdef _WIN32
    HANDLE in_handle = GetStdHandle(STD_INPUT_HANDLE);
    DWORD saved_mode = 0;
    const bool have_console = GetConsoleMode(in_handle, &saved_mode) != 0;
    if (have_console)
        SetConsoleMode(in_handle, saved_mode & ~ENABLE_ECHO_INPUT);

    std::string line;
    const bool ok = static_cast<bool>(std::getline(std::cin, line));

    if (have_console) SetConsoleMode(in_handle, saved_mode);
#else
    termios saved{};
    const bool have_tty = tcgetattr(STDIN_FILENO, &saved) == 0;
    if (have_tty) {
        termios hidden = saved;
        hidden.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden);
    }

    std::string line;
    const bool ok = static_cast<bool>(std::getline(std::cin, line));

    if (have_tty) tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved);
#endif

    std::cout << std::endl;
    if (!ok) return false;

    strip_trailing_newline(line);
    out = line;
    return true;
}

bool resolve_passphrase(const KeyOptions& opts, const std::string& prompt,
                        std::string& out, std::string& error) {
    if (!opts.keyfile.empty())
        return read_keyfile(opts.keyfile, out, error);

    if (const char* from_env = std::getenv(kEnvVar)) {
        std::string value(from_env);
        strip_trailing_newline(value);
        if (!value.empty()) {
            out = value;
            return true;
        }
    }

    if (!opts.allow_prompt || !stdin_is_tty()) {
        error = "no passphrase available: pass --keyfile or set " +
                std::string(kEnvVar);
        return false;
    }

    if (!read_hidden_line(prompt, out) || out.empty()) {
        error = "no passphrase entered";
        return false;
    }
    return true;
}

bool confirm_passphrase(const KeyOptions& opts, std::string& out,
                        std::string& error) {
    // A non-interactive source cannot be mistyped twice, so only a live
    // prompt needs confirming.
    if (!opts.keyfile.empty() || std::getenv(kEnvVar) != nullptr ||
        !opts.allow_prompt || !stdin_is_tty()) {
        return resolve_passphrase(opts, "Passphrase: ", out, error);
    }

    std::string first, second;
    if (!read_hidden_line("Passphrase: ", first) || first.empty()) {
        error = "no passphrase entered";
        return false;
    }
    if (!read_hidden_line("Confirm passphrase: ", second)) {
        error = "no passphrase entered";
        return false;
    }
    if (first != second) {
        error = "the two entries did not match";
        return false;
    }

    out = first;
    return true;
}

}  // namespace pcs
