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
    src/core/registry.cpp
    src/core/di_container.cpp
    src/core/module_loader.cpp
)

add_library(dvargosh_core SHARED ${CORE_SOURCES})
target_link_libraries(dvargosh_core PUBLIC ${EXTRA_LIBS})
target_include_directories(dvargosh_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Dynamic Modules (Plugins)
macro(add_dvargosh_module MODULE_NAME SOURCE_FILE)
    add_library(mod_${MODULE_NAME} SHARED ${SOURCE_FILE})
    target_link_libraries(mod_${MODULE_NAME} PRIVATE dvargosh_core)
    target_include_directories(mod_${MODULE_NAME} PRIVATE include)
    set_target_properties(mod_${MODULE_NAME} PROPERTIES
        PREFIX "lib"
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/modules
    )
endmacro()

add_dvargosh_module(logger modules/logger/logger_module.cpp)
add_dvargosh_module(math modules/math/math_module.cpp)
add_dvargosh_module(worker modules/worker/worker_module.cpp)

# Main Executable / Demo CLI
add_executable(dvargosh src/main.cpp)
target_link_libraries(dvargosh PRIVATE dvargosh_core)
target_include_directories(dvargosh PRIVATE include)
add_dependencies(dvargosh mod_logger mod_math mod_worker)

# Test Suite
enable_testing()

set(TEST_SOURCES
    tests/test_main.cpp
    tests/test_crypto.cpp
    tests/test_permissions.cpp
    tests/test_secured_memory.cpp
    tests/test_registry_di.cpp
    tests/test_module_lifecycle.cpp
)

add_executable(dvargosh_tests ${TEST_SOURCES})
target_link_libraries(dvargosh_tests PRIVATE dvargosh_core)
target_include_directories(dvargosh_tests PRIVATE include tests)

add_test(NAME UnitTests COMMAND dvargosh_tests)
add_test(NAME IntegrationDemo COMMAND dvargosh --modules ${CMAKE_BINARY_DIR}/modules)
