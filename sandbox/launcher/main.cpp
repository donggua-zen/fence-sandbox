// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 AI Sandbox Contributors
//
// @file main.cpp
// @brief Thin platform entry point.
//
// On Windows, wmain() converts wide-character arguments to UTF-8 before
// delegating to the shared ParseArgs/run pipeline. On Linux, main()
// receives UTF-8 directly from the OS.

#include "config.h"
#include "platform.h"

#ifdef _WIN32
// ============================================================
//  Windows entry point
// ============================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>

/**
 * @brief Convert a wide-character string to UTF-8.
 *
 * Windows provides arguments as wchar_t; the shared config parser works with
 * char* UTF-8, so we convert before forwarding.
 *
 * @param wstr  Null-terminated wide string (may be NULL or empty)
 * @return UTF-8 encoded std::string (empty if input is NULL/empty)
 */
static std::string wideToUtf8(const wchar_t* wstr) {
    if (!wstr || !*wstr) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return std::string();
    std::string str(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &str[0], len, NULL, NULL);
    return str;
}

int wmain(int argc, wchar_t* argv[]) {
    // Convert wide args to UTF-8 for the shared parser
    std::vector<std::string> utf8_args;
    utf8_args.reserve(argc);
    for (int i = 0; i < argc; i++)
        utf8_args.push_back(wideToUtf8(argv[i]));

    // Build char* array for ParseArgs
    std::vector<char*> c_args;
    c_args.reserve(argc);
    for (auto& s : utf8_args)
        c_args.push_back(s.data());

    sandbox::Config cfg;
    if (!sandbox::ParseArgs(argc, c_args.data(), cfg) || cfg.help || cfg.version || argc <= 1) {
        if (cfg.version) { sandbox::PrintVersion(); return 0; }
        if (!cfg.help && argc > 1) return 1;
        sandbox::PrintUsage();
        return cfg.help ? 0 : 1;
    }
    if (cfg.command.empty()) {
        fprintf(stderr, "Error: No command\n");
        return 1;
    }
    if (cfg.workspaces.empty()) {
        fprintf(stderr, "Error: --workspace is required\n");
        return 1;
    }

    return sandbox::run(cfg);
}

#else
// ============================================================
//  Linux entry point
// ============================================================

int main(int argc, char* argv[]) {
    sandbox::Config cfg;
    if (!sandbox::ParseArgs(argc, argv, cfg) || cfg.help || cfg.version || argc <= 1) {
        if (cfg.version) { sandbox::PrintVersion(); return 0; }
        if (!cfg.help && argc > 1) return 1;
        sandbox::PrintUsage();
        return cfg.help ? 0 : 1;
    }
    if (cfg.command.empty()) {
        fprintf(stderr, "Error: No command\n");
        return 1;
    }
    if (cfg.workspaces.empty()) {
        fprintf(stderr, "Error: --workspace is required\n");
        return 1;
    }

    return sandbox::run(cfg);
}

#endif
