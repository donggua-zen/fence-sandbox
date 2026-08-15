// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 AI Sandbox Contributors

#include "config.h"
#include "version.h"

#include <cstdio>
#include <cstring>

namespace sandbox {

void splitAndAppend(const std::string& str, std::vector<std::string>& out) {
    size_t start = 0;
    while (start < str.size()) {
        // Skip leading whitespace before the path
        while (start < str.size() && str[start] == ' ') start++;
        size_t end = str.find(',', start);
        if (end == std::string::npos) end = str.size();
        std::string path = str.substr(start, end - start);
        // Trim trailing whitespace
        while (!path.empty() && path.back() == ' ') path.pop_back();
        if (!path.empty()) out.push_back(path);
        start = end + 1;
    }
}

bool ParseArgs(int argc, char* argv[], Config& cfg) {
    for (int i = 1; i < argc; i++) {
        if (!std::strcmp(argv[i], "-c") || !std::strcmp(argv[i], "--command")) {
            if (i + 1 < argc) cfg.command = argv[++i];
            else { fprintf(stderr, "Error: -c requires a command\n"); return false; }
        } else if (!std::strcmp(argv[i], "--workspace")) {
            if (i + 1 < argc) {
                splitAndAppend(argv[++i], cfg.workspaces);
            } else { fprintf(stderr, "Error: --workspace requires a path\n"); return false; }
        } else if (!std::strcmp(argv[i], "--shell")) {
            if (i + 1 < argc) cfg.shell = argv[++i];
            else { fprintf(stderr, "Error: --shell requires a name\n"); return false; }
        } else if (!std::strcmp(argv[i], "--read-only")) {
            cfg.readOnly = true;
        } else if (!std::strcmp(argv[i], "--version")) {
            cfg.version = true;
        } else if (!std::strcmp(argv[i], "-h") || !std::strcmp(argv[i], "--help")) {
            cfg.help = true;
        } else {
            fprintf(stderr, "Error: Unknown argument: %s\n", argv[i]);
            return false;
        }
    }
    return true;
}

void PrintUsage() {
    printf("sandbox -- AI Sandbox\n");
    printf("\n");
    printf("Usage: sandbox -c <command> --workspace <path>[,<path>,...]\n");
    printf("\n");
    printf("Options:\n");
    printf("  -c, --command <cmd>           Command to execute\n");
    printf("  --workspace <path>[,<path>]   Workspace dir(s) (comma-separated)\n");
    printf("  --shell <name>                Command shell: Windows powershell|cmd (default powershell),\n");
    printf("                                Linux sh|bash (default sh)\n");
    printf("  --read-only                   Read-only mode: workspace is also read-only\n");
    printf("  --version                     Show version and exit\n");
    printf("  -h, --help                    Show this help\n");
}

void PrintVersion() {
    printf("sandbox %s\n", SANDBOX_VERSION_STRING);
}

} // namespace sandbox
