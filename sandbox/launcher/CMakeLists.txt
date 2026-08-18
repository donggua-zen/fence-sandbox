# sandbox -- AI Sandbox Launcher
# Platform-specific: Windows (Restricted Token + ACL) / Linux (Landlock) / macOS (Seatbelt)

add_executable(sandbox
    main.cpp
)

# Platform-specific source
if(WIN32)
    target_sources(sandbox PRIVATE platform_win.cpp)
elseif(APPLE)
    target_sources(sandbox PRIVATE platform_mac.cpp)
else()
    target_sources(sandbox PRIVATE platform_linux.cpp)
endif()

set_target_properties(sandbox PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if(MSVC)
    set_target_properties(sandbox PROPERTIES
        PDB_NAME "sandbox"
        PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        MSVC_RUNTIME_LIBRARY "MultiThreaded"
    )
    target_compile_options(sandbox PRIVATE /W4 /Zi /Gy /Gm- /utf-8)
    target_link_libraries(sandbox PRIVATE advapi32.lib userenv.lib)
else()
    target_compile_options(sandbox PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Link common library
target_link_libraries(sandbox PRIVATE sandbox_common)
