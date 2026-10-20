#include "dvargosh/dvargosh.hpp"
#include <string>

namespace dvargosh {

// Direct native C++ function decorated with attribution macro:
DVARGOSH_SERVICE(accelerator:cipher)
std::string accelerator_rot13(const std::string& input) {
    std::string s = input;
    for (char& c : s) {
        if (c >= 'a' && c <= 'z') c = 'a' + (c - 'a' + 13) % 26;
        else if (c >= 'A' && c <= 'Z') c = 'A' + (c - 'A' + 13) % 26;
    }
    return s;
}

} // namespace dvargosh
