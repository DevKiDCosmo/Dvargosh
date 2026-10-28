// Dvargosh Standard Library — stdtext module.
// The entire RPC surface is registered with the ServiceBinder: no DVARGOSH_EXPORT_FN
// boilerplate, no argument unpacking, no Value conversion in this file. Adding a
// service = one plain function in stdtext.services.cpp + one .fn<&...> line here.
#include "dvargosh/dvargosh.hpp"
#include "stdtext_api.hpp"

namespace dvargosh {

class StdTextModule : public IModule {
public:
    const ModuleManifest& manifest() const override {
        static ModuleManifest m = []() {
            ModuleManifest man;
            man.name = "stdtext";
            man.domain = "std:text";
            man.version = Version{1, 0, 0};
            man.description = "Dvargosh Standard Library: text manipulation services";
            man.author = "Dvargosh Team";
            man.requested_permissions = PermissionSet::standard_module();
            return man;
        }();
        return m;
    }

    Result<void> on_load(ModuleContext& ctx) override {
        return ctx.binds()
            .fn<&stdtext_api::trim>("stdtext.trim", "Trims whitespace from both ends")
            .fn<&stdtext_api::to_lower>("stdtext.to_lower", "Lowercases ASCII letters")
            .fn<&stdtext_api::to_upper>("stdtext.to_upper", "Uppercases ASCII letters")
            .fn<&stdtext_api::reverse>("stdtext.reverse", "Reverses the input string")
            .fn<&stdtext_api::replace>("stdtext.replace", "Replaces all occurrences (input, from, to)")
            .fn<&stdtext_api::repeat>("stdtext.repeat", "Repeats the input n times (input, times)")
            .fn<&stdtext_api::pad_left>("stdtext.pad_left", "Pads on the left to width (input, width, fill)")
            .fn<&stdtext_api::pad_right>("stdtext.pad_right", "Pads on the right to width (input, width, fill)")
            .fn<&stdtext_api::contains>("stdtext.contains", "Substring check (haystack, needle)")
            .fn<&stdtext_api::starts_with>("stdtext.starts_with", "Prefix check (input, prefix)")
            .fn<&stdtext_api::ends_with>("stdtext.ends_with", "Suffix check (input, suffix)")
            .fn<&stdtext_api::length>("stdtext.length", "Byte length of the input")
            .result();
    }

    Result<void> on_start(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_stop(ModuleContext&) override { return Result<void>::success(); }
    Result<void> on_unload(ModuleContext&) override { return Result<void>::success(); }
};

} // namespace dvargosh

DVARGOSH_EXPORT_MODULE(dvargosh::StdTextModule)
