# Common library: config parsing, shared across platforms
add_library(sandbox_common STATIC
    config.cpp
)

# Generate version.h from version.h.in using the version defined in the
# top-level project(AISandbox VERSION x.y.z) — the single source of truth.
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/version.h
    @ONLY
)

target_include_directories(sandbox_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

if(MSVC)
    target_compile_options(sandbox_common PRIVATE /W4 /Zi /Gy /Gm- /utf-8)
    set_target_properties(sandbox_common PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded"
    )
else()
    target_compile_options(sandbox_common PRIVATE -Wall -Wextra -Wpedantic)
endif()
