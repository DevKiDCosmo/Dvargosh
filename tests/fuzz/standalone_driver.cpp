// Standalone fuzz driver for toolchains without the libFuzzer runtime
// (macOS Xcode clang ships ASan but not libclang_rt.fuzzer_osx.a).
// Behavior: with file args, feeds each file to the harness once (ASan-instrumented);
// with no args, feeds builtin seeds plus any *.dylib/*.so found in ./modules and
// ./build/modules — real module binaries are excellent corpus for the header parser.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

static void run_case(const uint8_t* data, size_t size, const char* label) {
    fprintf(stderr, "[fuzz-driver] case: %s (%zu bytes)\n", label, size);
    LLVMFuzzerTestOneInput(data, size);
}

static void feed_file(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return;
    std::vector<uint8_t> buf;
    uint8_t chunk[4096];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) buf.insert(buf.end(), chunk, chunk + n);
    fclose(f);
    run_case(buf.data(), buf.size(), path);
}

static void feed_dir_dylibs(const char* dir) {
    DIR* d = opendir(dir);
    if (!d) return;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        std::string name = e->d_name;
        std::string path = std::string(dir) + "/" + name;
        if (name.size() > 4 && (name.rfind(".dylib") == name.size() - 6 || name.rfind(".so") == name.size() - 3)) {
            feed_file(path.c_str());
        }
    }
    closedir(d);
}

int main(int argc, char** argv) {
    if (argc > 1) {
        for (int i = 1; i < argc; ++i) feed_file(argv[i]);
        fprintf(stderr, "[fuzz-driver] done: %d file case(s)\n", argc - 1);
        return 0;
    }

    // Builtin seeds: structural edge cases for header/JSON/value parsers.
    static const uint8_t one = 0x41;
    run_case(nullptr, 0, "empty");
    run_case(&one, 1, "one-byte");
    const uint8_t magic[] = {0x44, 0x56, 0x41, 0x52, 0x47, 0x4F, 0x53, 0x48}; // "DVARGOSH"
    run_case(magic, sizeof(magic), "magic-only");
    std::vector<uint8_t> zeros(4096, 0);
    run_case(zeros.data(), zeros.size(), "zeros-4k");
    std::vector<uint8_t> ff(4096, 0xFF);
    run_case(ff.data(), ff.size(), "ff-4k");
    std::vector<uint8_t> alt(8192);
    for (size_t i = 0; i < alt.size(); ++i) alt[i] = static_cast<uint8_t>(i * 31 + (i % 7));
    run_case(alt.data(), alt.size(), "alt-pattern-8k");

    // Real-world corpus when available (ctest CWD = build dir).
    feed_dir_dylibs("./modules");
    feed_dir_dylibs("./build/modules");
    feed_dir_dylibs("./development_modules");
    feed_dir_dylibs("./build/development_modules");

    fprintf(stderr, "[fuzz-driver] done: builtin seed set\n");
    return 0;
}
