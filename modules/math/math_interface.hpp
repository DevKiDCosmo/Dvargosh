#pragma once

#include <cstdint>

namespace dvargosh {

class IMathService {
public:
    virtual ~IMathService() = default;
    virtual double add(double a, double b) = 0;
    virtual double multiply(double a, double b) = 0;
    virtual int64_t factorial(int64_t n) = 0;
};

} // namespace dvargosh
