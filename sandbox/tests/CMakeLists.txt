# Integration & security tests for sandbox
# Run with: ctest --output-on-failure

if(WIN32)
    # The default-shell cases invoke powershell.exe under the write-restricted
    # token, which hangs indefinitely on some environments (GitHub runners).
    # ctest therefore sets SANDBOX_TEST_SKIP_DEFAULT_SHELL to run the cmd-only
    # subset; run the scripts directly without the variable for full coverage.
    add_test(NAME integration_tests
        COMMAND "${CMAKE_CURRENT_LIST_DIR}/test_windows.bat" "$<TARGET_FILE:sandbox>"
    )
    add_test(NAME security_tests
        COMMAND "${CMAKE_CURRENT_LIST_DIR}/test_security_windows.bat" "$<TARGET_FILE:sandbox>"
    )
    set_tests_properties(integration_tests security_tests PROPERTIES
        ENVIRONMENT "SANDBOX_TEST_SKIP_DEFAULT_SHELL=1"
    )
elseif(APPLE)
    add_test(NAME integration_tests
        COMMAND bash "${CMAKE_CURRENT_LIST_DIR}/test_mac.sh" "$<TARGET_FILE:sandbox>"
    )
else()
    add_test(NAME integration_tests
        COMMAND bash "${CMAKE_CURRENT_LIST_DIR}/test_linux.sh" "$<TARGET_FILE:sandbox>"
    )
endif()
