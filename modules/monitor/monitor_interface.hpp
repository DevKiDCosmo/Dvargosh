#pragma once

#include <string>
#include <unordered_map>
#include <vector>

namespace dvargosh {

struct DomainMemoryInfo {
    std::string domain_name;
    size_t capacity_bytes = 0;
    size_t used_bytes = 0;
    size_t remaining_bytes = 0;
    size_t module_count = 0;
    size_t service_count = 0;
};

struct SystemMemoryOccupation {
    size_t host_current_allocated_bytes = 0;
    size_t host_peak_allocated_bytes = 0;
    size_t host_active_allocations = 0;
    size_t total_secured_capacity_bytes = 0;
    size_t total_secured_used_bytes = 0;
    std::vector<DomainMemoryInfo> domains;
};

class IMonitoringService {
public:
    virtual ~IMonitoringService() = default;
    virtual void record_metric(const std::string& name, double value) = 0;
    virtual double get_metric(const std::string& name) const = 0;
    virtual std::unordered_map<std::string, double> get_all_metrics() const = 0;
    virtual SystemMemoryOccupation get_memory_occupation() const = 0;
    virtual void dump_dashboard() const = 0;
};

} // namespace dvargosh
