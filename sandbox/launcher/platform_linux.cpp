// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 AI Sandbox Contributors
//
// @file platform_linux.cpp
// @brief Linux sandbox implementation using Landlock LSM.
//
// Strategy:
//   1. Query the kernel's Landlock ABI version.
//   2. Create a ruleset that handles all write-related access flags.
//   3. For each workspace directory, add an "allow write" rule (unless
//      --read-only mode is active, in which case all writes are denied).
//   4. Fork; the child applies the Landlock restriction to itself via
//      prctl(PR_SET_NO_NEW_PRIVS) + landlock_restrict_self(), then execs
//      sh -c <command>.
//   5. The parent waits for the child and returns its exit code.
//
// Landlock restrictions are enforced by the kernel and cannot be bypassed.
// They are automatically released when the process exits — no cleanup needed.
//
// If Landlock is unavailable (kernel < 5.13 or Docker seccomp blocks the
// syscall), the function prints an error and returns 1 without executing
// the command (fail-safe: never runs unsandboxed).

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "platform.h"
#include "config.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <cstdint>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

// ============================================================
//  Landlock ABI definitions
//
//  We try the kernel header first. If it is unavailable (older glibc or
//  cross-compiling), we define the structs and constants manually.
//  This ensures the code compiles even without linux/landlock.h.
// ============================================================
#if __has_include(<linux/landlock.h>)
#include <linux/landlock.h>
#endif

#ifndef LANDLOCK_ACCESS_FS_EXECUTE
/// Fallback Landlock definitions when kernel header is absent.
struct landlock_ruleset_attr {
    uint64_t handled_access_fs;
};
struct landlock_path_beneath_attr {
    uint64_t allowed_access;
    int32_t  parent_fd;
} __attribute__((packed));

#define LANDLOCK_CREATE_RULESET_VERSION 1
#define LANDLOCK_RULE_PATH_BENEATH      1

#define LANDLOCK_ACCESS_FS_EXECUTE       (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE    (1ULL << 1)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE   (1ULL << 2)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR     (1ULL << 3)
#define LANDLOCK_ACCESS_FS_MAKE_DIR      (1ULL << 4)
#define LANDLOCK_ACCESS_FS_MAKE_REG      (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK     (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO     (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK    (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SYM      (1ULL << 9)
#endif

/// ABI v2: refer (linking/removing) support, kernel 5.19+
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER         (1ULL << 11)
#endif
/// ABI v3: truncate support, kernel 6.2+
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE      (1ULL << 12)
#endif

/// Syscall numbers (generic syscall table, same across architectures).
#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif
#ifndef SYS_landlock_add_rule
#define SYS_landlock_add_rule 445
#endif
#ifndef SYS_landlock_restrict_self
#define SYS_landlock_restrict_self 446
#endif

/// All write-related access flags from ABI v1 (the baseline).
#define WRITE_ACCESS_MASK ( \
    LANDLOCK_ACCESS_FS_WRITE_FILE  | \
    LANDLOCK_ACCESS_FS_REMOVE_FILE | \
    LANDLOCK_ACCESS_FS_MAKE_CHAR   | \
    LANDLOCK_ACCESS_FS_MAKE_DIR    | \
    LANDLOCK_ACCESS_FS_MAKE_REG    | \
    LANDLOCK_ACCESS_FS_MAKE_SOCK   | \
    LANDLOCK_ACCESS_FS_MAKE_FIFO   | \
    LANDLOCK_ACCESS_FS_MAKE_BLOCK  | \
    LANDLOCK_ACCESS_FS_MAKE_SYM     \
)

// ============================================================
//  Signal forwarding to child process
// ============================================================

/// PID of the child process, used by the signal handler to forward signals.
static volatile sig_atomic_t g_child_pid = 0;

/**
 * @brief Forward a signal to the sandboxed child process.
 *
 * When the user presses Ctrl+C or sends SIGTERM to the sandbox process,
 * we forward the signal to the child so it can handle it gracefully.
 */
static void forward_signal(int sig) {
    if (g_child_pid > 0) {
        kill(g_child_pid, sig);
    }
}

// ============================================================
//  Main entry: set up Landlock sandbox and launch command
// ============================================================
namespace sandbox {

int run(const Config& cfg) {
    // --- Select command shell ---
    std::string shellPath;
    std::string shellName;
    if (cfg.shell.empty() || strcasecmp(cfg.shell.c_str(), "sh") == 0) {
        shellPath = "/bin/sh";
        shellName = "sh";
    } else if (strcasecmp(cfg.shell.c_str(), "bash") == 0) {
        shellPath = "/bin/bash";
        shellName = "bash";
    } else {
        fprintf(stderr, "sandbox: unsupported shell '%s' (Linux supports: sh, bash)\n",
                cfg.shell.c_str());
        return 1;
    }

    // Ensure workspace directories exist (create if missing, ignore if present)
    for (const auto& ws : cfg.workspaces) {
        mkdir(ws.c_str(), 0755);
    }

    // --- 1. Query Landlock ABI version ---
    // Returns the highest supported ABI version, or -1 if Landlock is unavailable.
    int abi = (int)syscall(SYS_landlock_create_ruleset, NULL, (size_t)0,
                           LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        fprintf(stderr, "sandbox: Landlock not supported (kernel < 5.13 or disabled)\n");
        fprintf(stderr, "sandbox: errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }

    // --- 2. Build write access mask based on ABI version ---
    // Higher ABI versions support more access flags; use them when available.
    uint64_t access_mask = WRITE_ACCESS_MASK;
    if (abi >= 2) {
        access_mask |= LANDLOCK_ACCESS_FS_REFER;      // kernel 5.19+
    }
    if (abi >= 3) {
        access_mask |= LANDLOCK_ACCESS_FS_TRUNCATE;   // kernel 6.2+
    }

    // --- 3. Create Landlock ruleset ---
    // The ruleset "handles" all write operations, meaning the kernel will
    // enforce restrictions on them. Rules added below exempt specific paths.
    struct landlock_ruleset_attr ruleset_attr = {};
    ruleset_attr.handled_access_fs = access_mask;

    int ruleset_fd = (int)syscall(SYS_landlock_create_ruleset,
                                  &ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "sandbox: landlock_create_ruleset failed: %s\n", strerror(errno));
        return 1;
    }

    // --- 4. Add "allow write" rules for each workspace ---
    // In read-only mode, skip this step entirely — all writes will be denied.
    if (!cfg.readOnly) {
        for (const auto& ws : cfg.workspaces) {
            struct landlock_path_beneath_attr path_attr = {};
            path_attr.allowed_access = access_mask;
            path_attr.parent_fd = open(ws.c_str(), O_PATH | O_CLOEXEC);
            if (path_attr.parent_fd < 0) {
                fprintf(stderr, "sandbox: cannot open workspace '%s': %s\n",
                        ws.c_str(), strerror(errno));
                close(ruleset_fd);
                return 1;
            }
            if (syscall(SYS_landlock_add_rule, ruleset_fd,
                        LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0) < 0) {
                fprintf(stderr, "sandbox: landlock_add_rule failed for '%s': %s\n",
                        ws.c_str(), strerror(errno));
                close(path_attr.parent_fd);
                close(ruleset_fd);
                return 1;
            }
            close(path_attr.parent_fd);
        }
    }

    // --- 5. Set up signal forwarding ---
    // Forward SIGINT, SIGTERM, SIGQUIT, SIGHUP to the child process.
    struct sigaction sa = {};
    sa.sa_handler = forward_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;  // Restart waitpid if interrupted by a signal
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);

    // --- 6. Fork ---
    // The child will inherit the Landlock ruleset fd and apply it to itself.
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "sandbox: fork failed: %s\n", strerror(errno));
        close(ruleset_fd);
        return 1;
    }

    if (pid == 0) {
        // === Child process ===

        // Ensure the child is killed if the parent dies (analogous to
        // Windows JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        prctl(PR_SET_PDEATHSIG, SIGKILL);

        // Race condition guard: if the parent already exited before we set
        // PR_SET_PDEATHSIG, getppid() will return 1 (init). Bail out.
        if (getppid() == 1) {
            _exit(1);
        }

        // Restore default signal handlers (the parent's handlers are irrelevant)
        signal(SIGINT,  SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        signal(SIGHUP,  SIG_DFL);

        // Change working directory to the first workspace (matches Windows
        // behavior where CreateProcessAsUserW sets lpCurrentDirectory).
        // This ensures relative paths in the command resolve inside the workspace.
        if (chdir(cfg.workspaces[0].c_str()) != 0) {
            fprintf(stderr, "sandbox: chdir to '%s' failed: %s\n",
                    cfg.workspaces[0].c_str(), strerror(errno));
            _exit(1);
        }

        // Apply Landlock restrictions to this process and all descendants.
        // PR_SET_NO_NEW_PRIVS is required before landlock_restrict_self().
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) < 0) {
            fprintf(stderr, "sandbox: landlock_restrict_self failed: %s\n", strerror(errno));
            _exit(1);
        }
        close(ruleset_fd);

        // Execute the user command via the selected shell
        execl(shellPath.c_str(), shellName.c_str(), "-c", cfg.command.c_str(), (char*)NULL);

        // If exec returns, it failed
        fprintf(stderr, "sandbox: exec failed: %s\n", strerror(errno));
        _exit(127);
    }

    // === Parent process ===
    close(ruleset_fd);
    g_child_pid = pid;

    // --- 7. Wait for child to complete ---
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        fprintf(stderr, "sandbox: waitpid failed: %s\n", strerror(errno));
        return 1;
    }

    g_child_pid = 0;

    // --- 8. Return the child's exit code ---
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        // Follow the shell convention: 128 + signal number
        return 128 + WTERMSIG(status);
    }
    return 1;
}

} // namespace sandbox
