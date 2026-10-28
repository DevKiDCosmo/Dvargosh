// Dvargosh Standard Library — stdtext service implementations.
// Pure C++ functions: no Value boxing, no registration boilerplate.
// The binder (stdtext_module.cpp) deduces signatures and handles the RPC layer.
#include "stdtext_api.hpp"
#include <algorithm>
#include <cctype>

namespace dvargosh::stdtext_api {

std::string trim(const std::string& input) {
    size_t begin = 0;
    size_t end = input.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(input[begin]))) ++begin;
    while (end > begin && std::isspace(static_cast<unsigned char>(input[end - 1]))) --end;
    return input.substr(begin, end - begin);
}

std::string to_lower(const std::string& input) {
    std::string out = input;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

std::string to_upper(const std::string& input) {
    std::string out = input;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return out;
}

std::string reverse(const std::string& input) {
    return std::string(input.rbegin(), input.rend());
}

std::string replace(const std::string& input, const std::string& from, const std::string& to) {
    if (from.empty()) return input;
    std::string out;
    out.reserve(input.size());
    size_t pos = 0;
    for (;;) {
        const size_t hit = input.find(from, pos);
        if (hit == std::string::npos) {
            out.append(input, pos, std::string::npos);
            break;
        }
        out.append(input, pos, hit - pos);
        out.append(to);
        pos = hit + from.size();
    }
    return out;
}

std::string repeat(const std::string& input, int64_t times) {
    if (times <= 0) return "";
    std::string out;
    out.reserve(input.size() * static_cast<size_t>(times));
    for (int64_t i = 0; i < times; ++i) out.append(input);
    return out;
}

std::string pad_left(const std::string& input, int64_t width, const std::string& fill) {
    if (width <= 0 || fill.empty()) return input;
    const int64_t missing = width - static_cast<int64_t>(input.size());
    if (missing <= 0) return input;
    std::string padding;
    padding.reserve(static_cast<size_t>(missing));
    for (int64_t i = 0; i < missing; ++i) padding.push_back(fill[i % fill.size()]);
    return padding + input;
}

std::string pad_right(const std::string& input, int64_t width, const std::string& fill) {
    if (width <= 0 || fill.empty()) return input;
    const int64_t missing = width - static_cast<int64_t>(input.size());
    if (missing <= 0) return input;
    std::string padding;
    padding.reserve(static_cast<size_t>(missing));
    for (int64_t i = 0; i < missing; ++i) padding.push_back(fill[i % fill.size()]);
    return input + padding;
}

bool contains(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return true;
    return haystack.find(needle) != std::string::npos;
}

bool starts_with(const std::string& input, const std::string& prefix) {
    return input.rfind(prefix, 0) == 0;
}

bool ends_with(const std::string& input, const std::string& suffix) {
    if (input.size() < suffix.size()) return false;
    return input.compare(input.size() - suffix.size(), suffix.size(), suffix) == 0;
}

int64_t length(const std::string& input) {
    return static_cast<int64_t>(input.size());
}

} // namespace dvargosh::stdtext_api
