// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 AI Sandbox Contributors

#pragma once

#include "config.h"

namespace sandbox {

/**
 * @brief Execute a command inside the OS-native sandbox.
 *
 * Sets up platform-specific filesystem restrictions (Restricted Token + ACL on
 * Windows, Landlock LSM on Linux), launches the command as a child process,
 * and waits for it to complete.
 *
 * Behavior:
 * - stdin/stdout/stderr are passed through transparently (no buffering).
 * - The child process exit code is returned to the caller.
 * - If the sandbox cannot be initialized, the function prints an error and
 *   returns 1 without executing the command (fail-safe: never runs unsandboxed).
 *
 * @param cfg  Parsed configuration (command, workspaces, read-only flag)
 * @return Exit code of the child process, or 1 on sandbox setup failure
 */
int run(const Config& cfg);

} // namespace sandbox
