#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

// A deliberately small test harness: registering a case is one macro, and the
// whole suite is a single binary with no external dependency.
namespace pcstest {

struct TestCase {
    std::string name;
    std::function<void()> body;
};

std::vector<TestCase>& registry();

struct Registrar {
    Registrar(const std::string& name, std::function<void()> body);
};

// Throws, so the runner can report the failure and carry on with the rest.
[[noreturn]] void fail(const char* file, int line, const std::string& detail);

std::string describe(const std::vector<uint8_t>& data);

int run_all();

}  // namespace pcstest

#define PCS_TEST(name)                                                  \
    static void name();                                                 \
    static ::pcstest::Registrar registrar_##name(#name, name);          \
    static void name()

#define CHECK(expr)                                                     \
    do {                                                                \
        if (!(expr)) ::pcstest::fail(__FILE__, __LINE__, #expr);        \
    } while (false)

#define CHECK_EQ(actual, expected)                                      \
    do {                                                                \
        auto pcs_a = (actual);                                          \
        auto pcs_b = (expected);                                        \
        if (!(pcs_a == pcs_b))                                          \
            ::pcstest::fail(__FILE__, __LINE__,                         \
                            std::string(#actual " == " #expected));     \
    } while (false)
