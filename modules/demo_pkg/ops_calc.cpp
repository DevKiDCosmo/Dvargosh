#include "dvargosh/dvargosh.hpp"
#include <cmath>

namespace dvargosh {

// Automatic function registration in another non-monolithic source file
DVARGOSH_EXPORT_FN(demo_pkg_worker_power, "demo_pkg:worker", "Auto-registered mathematical power function in worker subsystem") {
    double base = args.size() > 0 ? args[0].as_double() : 2.0;
    double exp = args.size() > 1 ? args[1].as_double() : 3.0;
    double result = std::pow(base, exp);
    return Result<Value>::success(Value(result));
}

} // namespace dvargosh
