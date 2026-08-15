// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 AI Sandbox Contributors

#pragma once

#include <string>
#include <vector>

namespace sandbox {

/**
 * @brief Holds parsed command-line configuration.
 *
 * Populated by ParseArgs() and consumed by the platform-specific run() function.
 */
struct Config {
    std::string command;                  ///< Shell command to execute (passed to the selected shell)
    std::vector<std::string> workspaces;  ///< Workspace directories where write access is permitted
    std::string shell;                    ///< Command shell: Windows powershell|cmd (default powershell), Linux sh|bash (default sh)
    bool help = false;                    ///< True if --help was requested
    bool version = false;                 ///< True if --version was requested
    bool readOnly = false;                ///< True if --read-only mode is active (deny all writes)
};

/**
 * @brief Split a comma-separated string into trimmed paths.
 *
 * Handles leading/trailing whitespace around each entry. Empty entries are skipped.
 * Used to parse the --workspace argument which accepts multiple comma-separated paths.
 *
 * @param str  Comma-separated input string (e.g. "/project/src, /project/shared")
 * @param out  Output vector to append parsed paths to
 */
void splitAndAppend(const std::string& str, std::vector<std::string>& out);

/**
 * @brief Parse command-line arguments into a Config struct.
 *
 * Recognized options:
 *   -c, --command <cmd>    Command to execute (required)
 *   --workspace <path>     Workspace directory, comma-separated for multiple (required)
 *   --shell <name>         Command shell: Windows powershell|cmd (default powershell),
 *                          Linux sh|bash (default sh)
 *   --read-only            Deny all writes, including inside workspace
 *   --version              Print version and exit
 *   -h, --help             Show usage
 *
 * @param argc  Argument count from main()
 * @param argv  Argument vector from main()
 * @param cfg   Output config struct to populate
 * @return true on success, false on parse error
 */
bool ParseArgs(int argc, char* argv[], Config& cfg);

/**
 * @brief Print usage information to stdout.
 */
void PrintUsage();

/**
 * @brief Print the program name and version to stdout (e.g. "sandbox 1.0.0").
 */
void PrintVersion();

} // namespace sandbox
