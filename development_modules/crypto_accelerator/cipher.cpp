#include "dvargosh/dvargosh.hpp"
#include <string>

namespace dvargosh {

DVARGOSH_EXPORT_FN(accelerator_rot13, "accelerator:cipher", "Caesar/ROT13 transform") {
    std::string s = args.empty() ? "" : args[0].to_string();
    for (char& c : s) {
        if (c >= 'a' && c <= 'z') c = 'a' + (c - 'a' + 13) % 26;
        else if (c >= 'A' && c <= 'Z') c = 'A' + (c - 'A' + 13) % 26;
    }
    return Result<Value>::success(Value(s));
}

} // namespace dvargosh
