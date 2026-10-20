cmake_minimum_required(VERSION 3.16)
project(Dvargosh VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler Warnings & Flags
if(MSVC)
    add_compile_options(/W4 /EHsc)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/modules)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Find Threads and DL libraries
find_package(Threads REQUIRED)
set(EXTRA_LIBS ${CMAKE_DL_LIBS} Threads::Threads)

# Include directories
include_directories(include)

# Core Library Sources
set(CORE_SOURCES
    src/core/crypto.cpp
    src/core/permissions.cpp
    src/core/secured_memory.cpp
    src/core/allocator.cpp
    src/core/resource_manager.cpp
    src/core/event_bus.cpp
    src/core/domain.cpp
    src/core/registry.cpp
    src/core/di_container.cpp
    src/core/module_loader.cpp
    src/core/module_catalog.cpp
)

add_library(dvargosh_core SHARED ${CORE_SOURCES})
target_link_libraries(dvargosh_core PUBLIC ${EXTRA_LIBS})
target_include_directories(dvargosh_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Include Auto-generated Module Targets (from modules/Modules.cmake)
include(modules/Modules.cmake)

# Main Executable / Demo CLI
add_executable(dvargosh src/main.cpp)
target_link_libraries(dvargosh PRIVATE dvargosh_core)
target_include_directories(dvargosh PRIVATE include)
if(DVARGOSH_ALL_MODULE_TARGETS)
    add_dependencies(dvargosh ${DVARGOSH_ALL_MODULE_TARGETS})
endif()

# Test Suite
enable_testing()

set(CORE_TEST_SOURCES
    tests/test_main.cpp
    tests/test_crypto.cpp
    tests/test_permissions.cpp
    tests/test_secured_memory.cpp
    tests/test_registry_di.cpp
    tests/test_module_lifecycle.cpp
    tests/test_violations.cpp
    tests/test_domains.cpp
)

set(MODULE_TEST_SOURCES
    modules/logger/test/test_logger.cpp
    modules/math/test/test_math.cpp
    modules/worker/test/test_worker.cpp
    modules/monitor/test/test_monitor.cpp
    modules/demo_pkg/test/test_demo_pkg.cpp
)

add_executable(dvargosh_tests ${CORE_TEST_SOURCES} ${MODULE_TEST_SOURCES})
target_link_libraries(dvargosh_tests PRIVATE dvargosh_core)
target_include_directories(dvargosh_tests PRIVATE include tests modules)
if(DVARGOSH_ALL_MODULE_TARGETS)
    add_dependencies(dvargosh_tests ${DVARGOSH_ALL_MODULE_TARGETS})
endif()

add_test(NAME UnitTests COMMAND dvargosh_tests)
add_test(NAME IntegrationDemo COMMAND dvargosh --modules ${CMAKE_BINARY_DIR}/modules)
