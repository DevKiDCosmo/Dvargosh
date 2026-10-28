#pragma once

// Dvargosh Standard Library — stdtext (text manipulation services)
// Plain, testable C++ functions; registration happens in stdtext_module.cpp
// via the ServiceBinder (no marker boilerplate, no manual Value boxing).

#include <cstdint>
#include <string>

namespace dvargosh::stdtext_api {

std::string trim(const std::string& input);
std::string to_lower(const std::string& input);
std::string to_upper(const std::string& input);
std::string reverse(const std::string& input);
std::string replace(const std::string& input, const std::string& from, const std::string& to);
std::string repeat(const std::string& input, int64_t times);
std::string pad_left(const std::string& input, int64_t width, const std::string& fill);
std::string pad_right(const std::string& input, int64_t width, const std::string& fill);
bool contains(const std::string& haystack, const std::string& needle);
bool starts_with(const std::string& input, const std::string& prefix);
bool ends_with(const std::string& input, const std::string& suffix);
int64_t length(const std::string& input);

} // namespace dvargosh::stdtext_api
