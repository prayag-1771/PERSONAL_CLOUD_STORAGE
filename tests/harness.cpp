#include "harness.hpp"

#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>

using namespace std;

namespace pcstest {
namespace {

struct Failure : runtime_error {
    explicit Failure(const string& what) : runtime_error(what) {}
};

}  // namespace

vector<TestCase>& registry() {
    static vector<TestCase> cases;
    return cases;
}

Registrar::Registrar(const string& name, function<void()> body) {
    registry().push_back(TestCase{name, move(body)});
}

void fail(const char* file, int line, const string& detail) {
    throw Failure(string(file) + ":" + to_string(line) + "  " + detail);
}

string describe(const vector<uint8_t>& data) {
    string out = "[" + to_string(data.size()) + " bytes]";
    return out;
}

int run_all() {
    int passed = 0;
    vector<string> failures;

    for (const TestCase& test : registry()) {
        try {
            test.body();
            passed++;
        } catch (const exception& e) {
            failures.push_back(test.name + "\n      " + e.what());
        } catch (...) {
            failures.push_back(test.name + "\n      unknown exception");
        }
    }

    cout << passed << " passed";
    if (!failures.empty()) {
        cout << ", " << failures.size() << " FAILED\n";
        for (const string& failure : failures) cout << "  FAIL  " << failure << "\n";
        return 1;
    }
    cout << ", all good (" << registry().size() << " tests)\n";
    return 0;
}

}  // namespace pcstest

int main() { return pcstest::run_all(); }
