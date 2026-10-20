#include "dvargosh/dvargosh.hpp"
#include <string>

namespace dvargosh {

DVARGOSH_SERVICE(captives:hello_world)
std::string hello_world(const std::string& input) {
    return "HELLO_WORLD_" + input;
}

} // namespace dvargosh
