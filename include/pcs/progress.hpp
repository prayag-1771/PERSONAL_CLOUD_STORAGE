#pragma once

#include <cstdint>
#include <string>

namespace pcs {

// A single-line progress bar that repaints in place. Quiet mode turns it into
// a no-op, which is what the autosync daemon uses.
class ProgressBar {
public:
    explicit ProgressBar(std::string label, bool enabled = true);

    void update(uint64_t done, uint64_t total);
    void finish();

private:
    std::string label_;
    bool enabled_;
    bool done_printed_ = false;
    int last_percent_ = -1;
};

std::string human_size(uint64_t bytes);

}  // namespace pcs
