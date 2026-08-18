#pragma once

#include <string>

// Where the passphrase comes from. Interactive use prompts with echo
// disabled; unattended use (the autosync daemon, scripts, tests) supplies it
// through the environment or a key file so nothing has to be typed.
namespace pcs {

struct KeyOptions {
    std::string keyfile;      // --keyfile PATH
    bool allow_prompt = true; // false for non-interactive contexts
};

// Resolution order: --keyfile, then $PCS_PASSPHRASE, then a terminal prompt.
// Returns false with `error` set when no source is available.
bool resolve_passphrase(const KeyOptions& opts, const std::string& prompt,
                        std::string& out, std::string& error);

// Prompts twice and checks the two entries match. Used when sealing a file
// for the first time, where a typo would make the data unrecoverable.
bool confirm_passphrase(const KeyOptions& opts, std::string& out,
                        std::string& error);

// Reads a line from the terminal without echoing it.
bool read_hidden_line(const std::string& prompt, std::string& out);

}  // namespace pcs
