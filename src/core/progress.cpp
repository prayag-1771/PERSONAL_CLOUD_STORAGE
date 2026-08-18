#include "pcs/progress.hpp"

#include <cstdio>
#include <iostream>
#include <utility>

namespace pcs {

ProgressBar::ProgressBar(std::string label, bool enabled)
    : label_(std::move(label)), enabled_(enabled) {}

void ProgressBar::update(uint64_t done, uint64_t total) {
    if (!enabled_ || done_printed_) return;

    int percent = total > 0
                      ? static_cast<int>((done * 100) / total)
                      : 100;
    if (percent > 100) percent = 100;

    // Repainting on every call makes a large transfer spend real time on
    // terminal I/O, so only redraw when the number actually changes.
    if (percent == last_percent_ && done < total) return;
    last_percent_ = percent;

    const int width = 30;
    int filled = width * percent / 100;

    std::cout << "\r  " << label_ << " [";
    for (int i = 0; i < width; i++) std::cout << (i < filled ? '#' : '.');
    std::cout << "] " << percent << "%  " << human_size(done) << " / "
              << human_size(total) << "   " << std::flush;

    if (total > 0 && done >= total) finish();
}

void ProgressBar::finish() {
    if (!enabled_ || done_printed_) return;
    done_printed_ = true;
    std::cout << std::endl;
}

std::string human_size(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        unit++;
    }

    char buf[64];
    if (unit == 0)
        std::snprintf(buf, sizeof(buf), "%llu B",
                      static_cast<unsigned long long>(bytes));
    else
        std::snprintf(buf, sizeof(buf), "%.1f %s", value, units[unit]);
    return std::string(buf);
}

}  // namespace pcs
