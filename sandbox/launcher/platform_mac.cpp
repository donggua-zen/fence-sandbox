// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 AI Sandbox Contributors
//
// @file platform_mac.cpp
// @brief macOS sandbox implementation using Seatbelt (sandbox-exec).
//
// Strategy:
//   1. Resolve every workspace to its canonical (real) path, creating the
//      directory if it does not exist. Seatbelt matches `subpath` filters
//      against the kernel-resolved path (e.g. /var -> /private/var), so we
//      must use realpath() output or writes silently fail even inside the
//      workspace.
//   2. Generate an SBPL profile that allows everything by default but denies
//      all file writes outside the workspace directories. This mirrors the
//      project's semantics: only writes are restricted (reads, network, CPU,
//      etc. are left untouched).
//   3. Fork; the child chdirs to the first workspace and execs
//      /usr/bin/sandbox-exec -f <profile> <shell> -c <command>.
//   4. The parent forwards signals to the child, waits for it and returns
//      its exit code.
//
// Fail-safe: if sandbox-exec cannot be run, run() returns 1 without
// executing the command (never runs unsandboxed).

#include "platform.h"
#include "config.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <strings.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

// ============================================================
//  Signal forwarding to child process
// ============================================================

/// PID of the child process, used by the signal handler to forward signals.
static volatile sig_atomic_t g_child_pid = 0;

static void forward_signal(int sig) {
    if (g_child_pid > 0) {
        kill(g_child_pid, sig);
    }
}

// ============================================================
//  Workspace path resolution
// ============================================================

static bool mkdir_p(const std::string& path) {
    if (path.empty()) return false;
    std::string cur;
    for (size_t i = 0; i < path.size(); i++) {
        cur += path[i];
        if (path[i] == '/') {
            if (cur.size() > 1) {
                if (mkdir(cur.c_str(), 0755) != 0 && errno != EEXIST) return false;
            }
        }
    }
    if (mkdir(path.c_str(), 0755) != 0 && errno != EEXIST) return false;
    return true;
}

/**
 * @brief Escape a path for embedding inside a double-quoted SBPL string.
 *
 * SBPL strings use backslash escapes, so a literal backslash must become
 * `\\` and a literal double quote must become `\"`. Without this, a
 * workspace containing either character breaks the generated profile with a
 * parse error (`unbound variable`).
 */
static std::string escapeSbpl(const std::string& path) {
    std::string out;
    out.reserve(path.size());
    for (char c : path) {
        if (c == '\\' || c == '"') out += '\\';
        out += c;
    }
    return out;
}

static bool resolveWorkspace(const std::string& ws, std::string& out) {
    if (!mkdir_p(ws)) {
        fprintf(stderr, "sandbox: cannot create workspace '%s': %s\n",
                ws.c_str(), strerror(errno));
        return false;
    }
    char resolved[PATH_MAX];
    if (!realpath(ws.c_str(), resolved)) {
        fprintf(stderr, "sandbox: cannot resolve workspace '%s': %s\n",
                ws.c_str(), strerror(errno));
        return false;
    }
    out.assign(resolved);
    return true;
}

// ============================================================
//  Main entry: set up Seatbelt sandbox and launch command
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
    } else if (strcasecmp(cfg.shell.c_str(), "zsh") == 0) {
        shellPath = "/bin/zsh";
        shellName = "zsh";
    } else {
        fprintf(stderr, "sandbox: unsupported shell '%s' (sh|bash|zsh)\n",
                cfg.shell.c_str());
        return 1;
    }

    // --- Resolve all workspaces to canonical paths ---
    std::vector<std::string> real;
    real.reserve(cfg.workspaces.size());
    for (const auto& ws : cfg.workspaces) {
        std::string rp;
        if (!resolveWorkspace(ws, rp)) return 1;
        real.push_back(rp);
    }

    // --- Build the SBPL profile ---
    // Allow everything except file writes outside any workspace. This
    // restricts writes only and leaves reads, network, CPU, etc. untouched,
    // matching the project's sandbox semantics.
    std::string profile = "(version 1)\n(allow default)\n";
    if (cfg.readOnly) {
        // Read-only mode: deny all file writes.
        profile += "(deny file-write*)\n";
    } else {
        profile += "(deny file-write* (require-all (subpath \"/\")\n";
        for (const auto& rp : real) {
            std::string esc = escapeSbpl(rp);
            profile += "    (require-not (subpath \"" + esc + "\"))\n";
        }
        profile += "))\n";
    }

    // --- Write the profile to a temporary file ---
    char tmpl[] = "/tmp/fence-sandbox.XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        fprintf(stderr, "sandbox: mkstemp failed: %s\n", strerror(errno));
        return 1;
    }
    if (dprintf(fd, "%s", profile.c_str()) < 0) {
        fprintf(stderr, "sandbox: cannot write profile: %s\n", strerror(errno));
        close(fd);
        unlink(tmpl);
        return 1;
    }
    close(fd);

    // --- Set up signal forwarding ---
    struct sigaction sa = {};
    sa.sa_handler = forward_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);

    // --- Fork ---
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "sandbox: fork failed: %s\n", strerror(errno));
        unlink(tmpl);
        return 1;
    }

    if (pid == 0) {
        // === Child process ===

        // Restore default signal handlers (the parent's handlers are irrelevant)
        signal(SIGINT,  SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        signal(SIGHUP,  SIG_DFL);

        // Change working directory to the first workspace so relative paths
        // in the command resolve inside the workspace.
        if (chdir(cfg.workspaces[0].c_str()) != 0) {
            fprintf(stderr, "sandbox: chdir to '%s' failed: %s\n",
                    cfg.workspaces[0].c_str(), strerror(errno));
            _exit(1);
        }

        // Run sandbox-exec, which applies the profile and then execs the
        // requested shell/command. Any failure here means we bail out.
        execl("/usr/bin/sandbox-exec", "sandbox-exec",
              "-f", tmpl,
              shellPath.c_str(), "-c", cfg.command.c_str(), (char*)NULL);

        fprintf(stderr, "sandbox: exec sandbox-exec failed: %s\n", strerror(errno));
        _exit(1);
    }

    // === Parent process ===
    g_child_pid = pid;

    // --- Wait for child to complete ---
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        fprintf(stderr, "sandbox: waitpid failed: %s\n", strerror(errno));
        unlink(tmpl);
        return 1;
    }

    g_child_pid = 0;

    // The child has exited; the temporary profile is no longer needed.
    unlink(tmpl);

    // --- Return the child's exit code ---
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        // Follow the shell convention: 128 + signal number
        return 128 + WTERMSIG(status);
    }
    return 1;
}

} // namespace sandbox
