// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 AI Sandbox Contributors
//
// @file platform_win.cpp
// @brief Windows sandbox implementation with dual backend strategy.
//
// Primary backend (Windows 11 24H2+):
//   Experimental_CreateProcessInSandbox — AppContainer-based isolation with
//   declarative filesystem rules via FlatBuffer SandboxSpec. Zero ACL footprint.
//
// Fallback backend (all Windows versions):
//   Restricted Token + ACL — Generate a random SID, grant it GENERIC_WRITE on
//   workspace directories, create a WRITE_RESTRICTED token, launch the process.
//   Cleanup removes the ACE and lock file on completion.
//
// Backend selection is capability-probing: load processmodel.dll, resolve the
// API, attempt the call. If unavailable or it fails, fall back silently.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <accctrl.h>
#include <wincrypt.h>
#include <stdio.h>
#include <wchar.h>
#include <string>
#include <vector>
#include <utility>

#include "platform.h"
#include "config.h"

/// Remove ACE and lock file after each command (set to 0 to disable cleanup).
#define CLEANUP_AFTER_EACH_COMMAND 1

/// Heartbeat thread updates lock file every 10 minutes.
#define LOCK_UPDATE_INTERVAL_MS  (10 * 60 * 1000)

/// Lock files older than 30 minutes are considered stale (process crashed).
#define LOCK_EXPIRE_THRESHOLD_MS (30 * 60 * 1000)

// ============================================================
//  UTF-8 <-> Wide string conversion
// ============================================================

/**
 * @brief Convert a UTF-8 std::string to a std::wstring.
 *
 * The Windows sandbox APIs (ACL, CreateProcess, etc.) require wide strings.
 */
static std::wstring utf8ToWide(const std::string& str) {
    if (str.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    if (len <= 0) return std::wstring();
    std::wstring wide(len - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wide[0], len);
    return wide;
}

/**
 * @brief Convert a std::wstring to UTF-8 std::string.
 *
 * Needed for FlatBuffer sandbox spec, which uses UTF-8 strings.
 */
static std::string wideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, NULL, 0, NULL, NULL);
    if (len <= 0) return std::string();
    std::string utf8(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &utf8[0], len, NULL, NULL);
    return utf8;
}

// ============================================================
//  FlatBuffer SandboxSpec builder for Experimental_CreateProcessInSandbox
// ============================================================
//
// Schema (from Microsoft MXC BaseContainerSpecification.fbs):
//   table SandboxSpec {
//     version:string (required);             // field 0
//     app_container:bool = false;            // field 1
//     integrity_level:uint32 = 0 (deprecated);  // field 2
//     disallow_win32k_system_calls:bool = false; // field 3
//     ui_restrictions:uint64 = 0;            // field 4
//     least_privilege:bool = false;          // field 5
//     capabilities:string;                   // field 6
//     fs_read_write:[string];                // field 7
//     fs_read_only:[string];                 // field 8
//     network_policy: NetworkPolicy;         // field 9
//     integrity:IntegrityLevel = system_default;  // field 10
//     fs_deny:[string];                      // field 11
//   }
//   root_type SandboxSpec;
//   file_identifier "SBOX";

/**
 * @brief Build a FlatBuffer SandboxSpec binary blob.
 *
 * Only version, app_container, and fs_read_write (or fs_read_only in
 * read-only mode) are populated. All other fields use schema defaults.
 *
 * @param readWritePaths  UTF-8 directory paths with read/write access
 * @param readOnlyPaths   UTF-8 directory paths with read-only access
 * @param outBuf          Output buffer receiving the FlatBuffer binary
 * @return true on success
 */
static bool buildSandboxSpec(
    const std::vector<std::string>& readWritePaths,
    const std::vector<std::string>& readOnlyPaths,
    std::vector<uint8_t>& outBuf
) {
    outBuf.clear();

    bool hasRW = !readWritePaths.empty();
    bool hasRO = !readOnlyPaths.empty();
    const auto& paths = hasRW ? readWritePaths : readOnlyPaths;

    // Lambda helpers for little-endian writes
    auto writeU16 = [&](uint16_t v) {
        outBuf.push_back((uint8_t)(v & 0xFF));
        outBuf.push_back((uint8_t)((v >> 8) & 0xFF));
    };
    auto writeU32 = [&](uint32_t v) {
        outBuf.push_back((uint8_t)(v & 0xFF));
        outBuf.push_back((uint8_t)((v >> 8) & 0xFF));
        outBuf.push_back((uint8_t)((v >> 16) & 0xFF));
        outBuf.push_back((uint8_t)((v >> 24) & 0xFF));
    };
    auto writeI32 = [&](int32_t v) { writeU32((uint32_t)v); };
    auto pad4 = [&]() {
        while (outBuf.size() % 4 != 0) outBuf.push_back(0);
    };

    // 1. Header (8 bytes): root offset placeholder + file identifier "SBOX"
    size_t headerPos = outBuf.size();
    writeU32(0);  // root offset placeholder (filled in at end)
    outBuf.push_back('S'); outBuf.push_back('B');
    outBuf.push_back('O'); outBuf.push_back('X');

    // 2. VTable (9 entries for fields 0-8)
    pad4();
    size_t vtablePos = outBuf.size();
    writeU16(4 + 2 * 9);  // vtable_size = 22
    writeU16(16);          // table_data_size = 16
    writeU16(4);   // field 0: version, at table+4
    writeU16(8);   // field 1: app_container, at table+8
    writeU16(0);   // field 2: not present
    writeU16(0);   // field 3: not present
    writeU16(0);   // field 4: not present
    writeU16(0);   // field 5: not present
    writeU16(0);   // field 6: not present
    writeU16(hasRW ? 12 : 0);  // field 7: fs_read_write
    writeU16(hasRO ? 12 : 0);  // field 8: fs_read_only

    // 3. Root Table (16 bytes)
    pad4();  // Align table start to 4 bytes
    size_t tablePos = outBuf.size();
    writeI32((int32_t)(tablePos - vtablePos));  // soffset to vtable

    size_t field0Pos = outBuf.size();  // version string offset slot
    writeU32(0);  // placeholder

    outBuf.push_back(1);  // field 1: app_container = true
    pad4();  // align for the next uint32 field

    size_t fieldVecPos = outBuf.size();  // vector offset slot
    writeU32(0);  // placeholder

    // 4. Vector of string offsets (fs_read_write or fs_read_only)
    pad4();
    size_t vecPos = outBuf.size();
    writeU32((uint32_t)paths.size());  // element count

    std::vector<size_t> stringOffsetSlots;
    for (size_t i = 0; i < paths.size(); i++) {
        stringOffsetSlots.push_back(outBuf.size());
        writeU32(0);  // placeholder for string offset
    }

    // 5. Version string "0.1.0"
    pad4();
    size_t versionPos = outBuf.size();
    const char* ver = "0.1.0";
    writeU32(5);  // length (excluding null)
    for (int i = 0; i < 5; i++) outBuf.push_back((uint8_t)ver[i]);
    outBuf.push_back(0);  // null terminator
    pad4();

    // 6. Workspace path strings
    std::vector<size_t> stringPositions;
    for (const auto& path : paths) {
        pad4();
        stringPositions.push_back(outBuf.size());
        writeU32((uint32_t)path.length());
        outBuf.insert(outBuf.end(), path.begin(), path.end());
        outBuf.push_back(0);  // null terminator
        pad4();
    }

    // 7. Fill in all offsets (relative to each offset's stored position)
    // Root table offset
    uint32_t rootOffset = (uint32_t)tablePos;
    memcpy(&outBuf[headerPos], &rootOffset, sizeof(rootOffset));

    // Version string offset (relative to field0Pos)
    uint32_t verOffset = (uint32_t)(versionPos - field0Pos);
    memcpy(&outBuf[field0Pos], &verOffset, sizeof(verOffset));

    // Vector offset (relative to fieldVecPos)
    if (!paths.empty()) {
        uint32_t vecOffset = (uint32_t)(vecPos - fieldVecPos);
        memcpy(&outBuf[fieldVecPos], &vecOffset, sizeof(vecOffset));
    }

    // String offsets in vector (relative to each slot position)
    for (size_t i = 0; i < paths.size(); i++) {
        uint32_t strOffset = (uint32_t)(stringPositions[i] - stringOffsetSlots[i]);
        memcpy(&outBuf[stringOffsetSlots[i]], &strOffset, sizeof(strOffset));
    }

    return true;
}

// ============================================================
//  AppContainer profile helpers (required before CreateProcessInSandbox
//  because the `identity` parameter must match a registered profile)
// ============================================================

#include <userenv.h>
#pragma comment(lib, "userenv.lib")  // for CreateAppContainerProfile / DeleteAppContainerProfile

/**
 * @brief Ensure the AppContainer profile for `identity` exists.
 *
 * `CreateAppContainerProfile` is idempotent: if the profile already exists it
 * returns HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS), which we treat as success.
 * This is required before Experimental_CreateProcessInSandbox will accept the
 * identity; otherwise the engine may fail with ERROR_CALL_NOT_IMPLEMENTED.
 *
 * @param identity  Profile name (wide)
 * @return true on success (profile exists), false otherwise
 */
static bool ensureAppContainerProfile(PCWSTR identity) {
    PSID unusedSid = NULL;
    HRESULT hr = CreateAppContainerProfile(
        identity,
        identity,             // DisplayName (use identity itself)
        L"AI Sandbox temp profile",  // Description
        NULL, 0,              // No extra capabilities
        &unusedSid
    );
    if (SUCCEEDED(hr) || hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
        if (unusedSid) FreeSid(unusedSid);
        return true;
    }
    fwprintf(stderr, L"sandbox: [diagnostic] CreateAppContainerProfile(\"%s\") hr=0x%08X\n",
             identity, (UINT32)hr);
    if (unusedSid) FreeSid(unusedSid);
    return false;
}

// ============================================================
//  Experimental_CreateProcessInSandbox API types and wrapper
// ============================================================

typedef BOOL (WINAPI *PFN_Experimental_CreateProcessInSandbox)(
    _In_opt_ LPCWSTR applicationName,
    _Inout_opt_ LPWSTR commandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES processAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES threadAttributes,
    BOOL inheritHandles,
    DWORD creationFlags,
    _In_opt_ LPVOID environment,
    _In_opt_ LPCWSTR currentDirectory,
    _In_ LPSTARTUPINFOW startupInfo,
    _In_ LPCWSTR identity,
    _In_reads_bytes_(sandboxSpecificationSize) LPCVOID sandboxSpecification,
    DWORD sandboxSpecificationSize,
    _Out_ LPPROCESS_INFORMATION processInformation
);

/**
 * @brief Try running the command via Experimental_CreateProcessInSandbox.
 *
 * Probes for processmodel.dll and the experimental API. If unavailable or
 * the call fails, returns -1 to signal the caller to fall back to the
 * Restricted Token approach.
 *
 * @param cmdLine    Full command line (shell + args + user command)
 * @param workingDir Working directory for the child process
 * @param wWorkspaces Workspace directories (for fs_read_write / fs_read_only)
 * @param readOnly   If true, workspaces are read-only
 * @return Exit code (>= 0) on success, or -1 to signal fallback
 */
static int runWithSandboxApi(
    const std::wstring& cmdLine,
    const std::wstring& workingDir,
    const std::vector<std::wstring>& wWorkspaces,
    bool readOnly
) {
    // 1. Load processmodel.dll from System32
    HMODULE hMod = LoadLibraryExW(L"processmodel.dll", NULL,
                                  LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!hMod) return -1;

    auto pfnCreate = (PFN_Experimental_CreateProcessInSandbox)
        GetProcAddress(hMod, "Experimental_CreateProcessInSandbox");
    if (!pfnCreate) {
        FreeLibrary(hMod);
        return -1;
    }

    // 2. Build the FlatBuffer SandboxSpec
    std::vector<std::string> rwPaths, roPaths;
    if (!readOnly) {
        for (const auto& ws : wWorkspaces)
            rwPaths.push_back(wideToUtf8(ws));
    } else {
        for (const auto& ws : wWorkspaces)
            roPaths.push_back(wideToUtf8(ws));
    }

    std::vector<uint8_t> specBuf;
    if (!buildSandboxSpec(rwPaths, roPaths, specBuf)) {
        FreeLibrary(hMod);
        return -1;
    }

    // 2.5 Diagnostic: hex dump first 64 bytes of spec to stderr
    // (temporary for debugging, can be removed later)
    {
        fwprintf(stderr, L"sandbox: [diagnostic] SandboxSpec size=%zu bytes, hex:\n",
                 specBuf.size());
        for (size_t i = 0; i < specBuf.size(); i += 16) {
            fwprintf(stderr, L"  %04zu: ", i);
            for (size_t j = 0; j < 16 && i + j < specBuf.size(); j++)
                fwprintf(stderr, L"%02X ", specBuf[i + j]);
            fwprintf(stderr, L"\n");
        }
    }

    // 3. Use a stable identity (AppContainer profile is persistent, not ephemeral)
    //    Then ensure the profile is registered via CreateAppContainerProfile.
    static const WCHAR kIdentity[] = L"AISandbox.Container.v1";
    if (!ensureAppContainerProfile(kIdentity)) {
        // profile registration failed → API won't accept the identity, fall back
        FreeLibrary(hMod);
        return -1;
    }

    // 4. Set up STARTUPINFO with stdio handle passthrough
    HANDLE hStdin  = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hStderr = GetStdHandle(STD_ERROR_HANDLE);

    // Mark handles as inheritable so the sandbox engine can duplicate them
    // even though inheritHandles is FALSE.
    if (hStdin)  SetHandleInformation(hStdin,  HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    if (hStdout) SetHandleInformation(hStdout, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    if (hStderr) SetHandleInformation(hStderr, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdInput   = hStdin;
    si.hStdOutput  = hStdout;
    si.hStdError   = hStderr;

    // 5. Build mutable command line buffer
    WCHAR* cmdCopy = (WCHAR*)LocalAlloc(LPTR,
        (cmdLine.size() + 1) * sizeof(WCHAR));
    if (!cmdCopy) { FreeLibrary(hMod); return -1; }
    wcscpy_s(cmdCopy, cmdLine.size() + 1, cmdLine.c_str());

    // 6. Create Job Object (ensures child is killed if parent dies)
    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (hJob) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo = { 0 };
        jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                                &jobInfo, sizeof(jobInfo));
    }

    // 7. Launch the sandboxed process
    PROCESS_INFORMATION pi = {};
    BOOL ok = pfnCreate(
        NULL,               // applicationName (resolve from commandLine)
        cmdCopy,            // commandLine
        NULL,               // processAttributes (reserved)
        NULL,               // threadAttributes (reserved)
        FALSE,              // inheritHandles (must be FALSE)
        0,                  // creationFlags
        NULL,               // environment (inherit parent's)
        workingDir.c_str(),
        &si,
        kIdentity,
        specBuf.data(),
        (DWORD)specBuf.size(),
        &pi
    );

    LocalFree(cmdCopy);

    if (!ok) {
        // API call failed — fall back to Restricted Token
        if (hJob) CloseHandle(hJob);
        FreeLibrary(hMod);
        return -1;
    }

    FreeLibrary(hMod);

    // 8. Associate with Job Object and wait for completion
    if (hJob) AssignProcessToJobObject(hJob, pi.hProcess);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (hJob) CloseHandle(hJob);

    return (int)exitCode;
}

// ============================================================
//  Forward declarations
// ============================================================
static bool generateRandomSid(PSID* ppSid);
static bool ensureWorkspaceWriteAcl(PCWSTR workspace, PSID sid);
static bool removeWorkspaceWriteAcl(PCWSTR workspace, PSID sid);
static bool hasExplicitAllowWrite(PACL dacl, PSID sid);
static bool isSandboxSid(PSID sid);
static bool createLockFile(PCWSTR workspace, PSID sid);
static bool updateLockFile(PCWSTR workspace, PSID sid);
static bool deleteLockFile(PCWSTR workspace, PSID sid);
static bool isSidActive(PCWSTR workspace, PSID sid);
static void getLockFilePath(PCWSTR workspace, PSID sid, WCHAR* path, DWORD pathSize);
static DWORD WINAPI LockUpdateThreadProc(LPVOID lpParameter);

// ============================================================
//  Main entry: set up sandbox and launch command
// ============================================================
namespace sandbox {

int run(const Config& cfg) {
    // Convert UTF-8 config strings to wide for Windows APIs
    std::wstring wCommand = utf8ToWide(cfg.command);
    std::vector<std::wstring> wWorkspaces;
    for (const auto& ws : cfg.workspaces)
        wWorkspaces.push_back(utf8ToWide(ws));

    // Ensure all workspace directories exist (create if missing)
    for (const auto& ws : wWorkspaces)
        CreateDirectoryW(ws.c_str(), NULL);

    // --- Select command shell ---
    std::wstring shell = utf8ToWide(cfg.shell);
    std::wstring shellPath;
    std::wstring shellArgs;
    if (shell.empty() || _wcsicmp(shell.c_str(), L"cmd") == 0) {
        shellPath = L"cmd.exe";
        shellArgs = L"/c ";
    } else if (_wcsicmp(shell.c_str(), L"powershell") == 0 ||
               _wcsicmp(shell.c_str(), L"ps") == 0) {
        shellPath = L"powershell.exe";
        shellArgs = L"-NoProfile -NonInteractive -Command ";
    } else {
        fwprintf(stderr, L"sandbox: unsupported shell '%s' (Windows supports: powershell, cmd)\n",
                 shell.c_str());
        return 1;
    }

    // --- Build command line: <shell> <args> <command> ---
    std::wstring cmdLine = shellPath + L" " + shellArgs + wCommand;

    // --- Try modern Windows Sandbox API first (Windows 11 24H2+) ---
    // Falls back to Restricted Token on older Windows or if the API fails.
    {
        int sandboxResult = runWithSandboxApi(cmdLine, wWorkspaces[0], wWorkspaces, cfg.readOnly);
        if (sandboxResult >= 0) return sandboxResult;
        // sandboxResult == -1: API unavailable or call failed, fall through
    }

    // ================================================================
    //  Fallback: Restricted Token + ACL approach (all Windows versions)
    // ================================================================

    // --- 1. Open current process token for duplication ---
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken)) {
        fwprintf(stderr, L"sandbox: token error (%lu)\n", GetLastError());
        return 1;
    }

    // --- 2. Generate random workspace SID (skipped in read-only mode) ---
    PSID workspaceSid = NULL;
    HANDLE hHeartbeatThread = NULL;
    std::vector<std::pair<std::wstring, PSID>> wsList;
    if (!cfg.readOnly) {
        if (!generateRandomSid(&workspaceSid)) {
            fwprintf(stderr, L"sandbox: SID generation failed\n");
            CloseHandle(hToken);
            return 1;
        }

        // --- 3. Grant write access on each workspace dir + create lock files ---
        for (const auto& ws : wWorkspaces) {
            if (!ensureWorkspaceWriteAcl(ws.c_str(), workspaceSid)) {
                fwprintf(stderr, L"sandbox: ACL setup failed for %s\n", ws.c_str());
            }
            createLockFile(ws.c_str(), workspaceSid);
        }

        // --- 3.5 Start heartbeat thread for lock file maintenance ---
        for (const auto& ws : wWorkspaces) {
            wsList.emplace_back(ws, workspaceSid);
        }
        hHeartbeatThread = CreateThread(NULL, 0, LockUpdateThreadProc, &wsList, 0, NULL);
    }

    // --- 4. Create Restricted Token ---
    // Add Everyone SID as a restricting SID so that the token can only write
    // to objects explicitly granting access to one of the restricting SIDs.
    PSID everyoneSid = NULL, logonSid = NULL;
    ConvertStringSidToSidW(L"S-1-1-0", &everyoneSid);
    if (!cfg.readOnly) {
        // Extract the logon SID from the current token (needed for restricting)
        DWORD bufSize = 0;
        GetTokenInformation(hToken, TokenGroups, NULL, 0, &bufSize);
        PTOKEN_GROUPS groups = (PTOKEN_GROUPS)LocalAlloc(LPTR, bufSize);
        if (groups && GetTokenInformation(hToken, TokenGroups, groups, bufSize, &bufSize)) {
            for (DWORD i = 0; i < groups->GroupCount; i++) {
                if (groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) {
                    DWORD len = GetLengthSid(groups->Groups[i].Sid);
                    logonSid = (PSID)LocalAlloc(LPTR, len);
                    if (logonSid) CopySid(len, logonSid, groups->Groups[i].Sid);
                    break;
                }
            }
        }
        LocalFree(groups);
    }

    // Build the list of restricting SIDs for CreateRestrictedToken
    SID_AND_ATTRIBUTES restrictingSids[3] = {};
    DWORD numRestricting = 0;
    if (everyoneSid)  { restrictingSids[numRestricting].Sid = everyoneSid; numRestricting++; }
    if (!cfg.readOnly && logonSid)     { restrictingSids[numRestricting].Sid = logonSid;     numRestricting++; }
    if (!cfg.readOnly && workspaceSid) { restrictingSids[numRestricting].Sid = workspaceSid; numRestricting++; }

    HANDLE hRestrictedToken = NULL;
    BOOL ok = CreateRestrictedToken(
        hToken,
        DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED,
        0, NULL,          0, NULL,
        numRestricting, restrictingSids,
        &hRestrictedToken
    );
    CloseHandle(hToken);
    LocalFree(everyoneSid);
    LocalFree(logonSid);

    if (!ok) {
        fwprintf(stderr, L"sandbox: CreateRestrictedToken (%lu)\n", GetLastError());
        if (!cfg.readOnly) {
            if (hHeartbeatThread) { TerminateThread(hHeartbeatThread, 0); CloseHandle(hHeartbeatThread); }
            for (const auto& ws : wWorkspaces) {
                if (CLEANUP_AFTER_EACH_COMMAND) {
                    deleteLockFile(ws.c_str(), workspaceSid);
                    removeWorkspaceWriteAcl(ws.c_str(), workspaceSid);
                }
            }
        }
        LocalFree(workspaceSid);
        return 1;
    }

    // --- 5. Create Job Object (ensures child is killed if parent dies) ---
    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (hJob) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo = { 0 };
        jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jobInfo, sizeof(jobInfo));
    }

    // --- 6. Launch command with restricted token ---
    // Pass through stdin/stdout/stderr handles for transparent I/O
    HANDLE hParentStdin  = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hParentStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hParentStderr = GetStdHandle(STD_ERROR_HANDLE);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdInput   = hParentStdin;
    si.hStdOutput  = hParentStdout;
    si.hStdError   = hParentStderr;

    // cmdLine was already built above (before the sandbox API attempt)
    WCHAR* cmdCopy = (WCHAR*)LocalAlloc(LPTR, (cmdLine.size() + 1) * sizeof(WCHAR));
    if (cmdCopy) wcscpy_s(cmdCopy, cmdLine.size() + 1, cmdLine.c_str());

    PROCESS_INFORMATION pi;
    // NOTE: lpApplicationName stays NULL so Windows resolves the module name
    // from the first token of lpCommandLine. Passing a relative name here
    // (e.g. "powershell.exe") would only search the current directory, not PATH.
    ok = CreateProcessAsUserW(
        hRestrictedToken,
        NULL, cmdCopy,
        NULL, NULL,
        TRUE,   // Inherit handles (needed for stdin/stdout/stderr passthrough)
        0,      // No special creation flags
        NULL,
        wWorkspaces[0].c_str(),  // Set working directory to first workspace
        &si, &pi
    );
    LocalFree(cmdCopy);

    if (!ok) {
        fwprintf(stderr, L"sandbox: CreateProcessAsUserW (%lu)\n", GetLastError());
        CloseHandle(hRestrictedToken);
        if (hJob) CloseHandle(hJob);
        if (!cfg.readOnly) {
            if (hHeartbeatThread) { TerminateThread(hHeartbeatThread, 0); CloseHandle(hHeartbeatThread); }
            for (const auto& ws : wWorkspaces) {
                if (CLEANUP_AFTER_EACH_COMMAND) {
                    deleteLockFile(ws.c_str(), workspaceSid);
                    removeWorkspaceWriteAcl(ws.c_str(), workspaceSid);
                }
            }
        }
        LocalFree(workspaceSid);
        return 1;
    }

    // Associate child process with the job object (auto-kill on parent exit)
    if (hJob) AssignProcessToJobObject(hJob, pi.hProcess);

    // Wait for the child process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    CloseHandle(hRestrictedToken);
    if (hJob) CloseHandle(hJob);

    // --- 8. Stop heartbeat thread and clean up ACEs / lock files ---
    if (!cfg.readOnly) {
        if (hHeartbeatThread) {
            TerminateThread(hHeartbeatThread, 0);
            CloseHandle(hHeartbeatThread);
        }

        if (CLEANUP_AFTER_EACH_COMMAND) {
            for (const auto& ws : wWorkspaces) {
                deleteLockFile(ws.c_str(), workspaceSid);
                removeWorkspaceWriteAcl(ws.c_str(), workspaceSid);
            }
        }
    }

    LocalFree(workspaceSid);
    return (int)exitCode;
}

} // namespace sandbox

// ============================================================
//  Helper functions
// ============================================================

/**
 * @brief Generate a cryptographically random SID for sandbox identification.
 *
 * Uses CryptGenRandom to produce 128 bits of randomness, formatted as
 * S-1-5-10-{rand}-{rand}-{rand}-{rand}. The S-1-5-10 prefix (Security/NT Authority
 * sub-authority 10) is repurposed as a sandbox-specific namespace.
 *
 * @param ppSid  Output pointer to receive the allocated SID (caller must LocalFree)
 * @return true on success, false on failure
 */
bool generateRandomSid(PSID* ppSid) {
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return false;
    DWORD randVals[4];
    if (!CryptGenRandom(hProv, sizeof(randVals), (BYTE*)randVals)) {
        CryptReleaseContext(hProv, 0); return false;
    }
    CryptReleaseContext(hProv, 0);
    WCHAR sz[64];
    _snwprintf_s(sz, _TRUNCATE, L"S-1-5-10-%lu-%lu-%lu-%lu",
                  randVals[0], randVals[1], randVals[2], randVals[3]);
    return ConvertStringSidToSidW(sz, ppSid) != FALSE;
}

/**
 * @brief Check whether a SID belongs to the sandbox namespace (S-1-5-10-*).
 *
 * Used to identify and clean up stale ACEs left by previous sandbox invocations
 * that crashed before cleanup.
 *
 * @param sid  SID to check (may be NULL)
 * @return true if the SID is in the sandbox namespace, false otherwise
 */
bool isSandboxSid(PSID sid) {
    if (!sid) return false;
    SID_IDENTIFIER_AUTHORITY* auth = GetSidIdentifierAuthority(sid);
    if (auth->Value[5] != 5) return false;
    DWORD subAuthCount = *GetSidSubAuthorityCount(sid);
    if (subAuthCount != 5) return false;
    if (*GetSidSubAuthority(sid, 0) != 10) return false;
    return true;
}

/**
 * @brief Build the path to the lock file for a given workspace and SID.
 *
 * The lock file is stored at <workspace>/.sandbox/<sid>.lock and is used
 * for heartbeat-based zombie detection.
 *
 * @param workspace  Workspace directory path (wide)
 * @param sid        Sandbox SID
 * @param path       Output buffer for the lock file path
 * @param pathSize   Size of the output buffer in characters
 */
static void getLockFilePath(PCWSTR workspace, PSID sid, WCHAR* path, DWORD pathSize) {
    WCHAR* sidStr = NULL;
    ConvertSidToStringSidW(sid, &sidStr);
    if (sidStr) {
        _snwprintf_s(path, pathSize, _TRUNCATE, L"%s\\.sandbox\\%s.lock", workspace, sidStr);
        LocalFree(sidStr);
    }
}

/**
 * @brief Create a hidden lock file for heartbeat tracking.
 *
 * Also creates the .sandbox subdirectory if it does not exist.
 *
 * @param workspace  Workspace directory path
 * @param sid        Sandbox SID
 * @return true on success, false on failure
 */
bool createLockFile(PCWSTR workspace, PSID sid) {
    WCHAR lockDir[MAX_PATH];
    _snwprintf_s(lockDir, _TRUNCATE, L"%s\\.sandbox", workspace);
    CreateDirectoryW(lockDir, NULL);

    WCHAR lockPath[MAX_PATH];
    getLockFilePath(workspace, sid, lockPath, MAX_PATH);

    HANDLE hFile = CreateFileW(lockPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    CloseHandle(hFile);
    return true;
}

/**
 * @brief Touch the lock file to update its last-write timestamp.
 *
 * Called periodically by the heartbeat thread to signal that the sandbox
 * process is still alive.
 *
 * @param workspace  Workspace directory path
 * @param sid        Sandbox SID
 * @return true on success, false on failure
 */
bool updateLockFile(PCWSTR workspace, PSID sid) {
    WCHAR lockPath[MAX_PATH];
    getLockFilePath(workspace, sid, lockPath, MAX_PATH);

    HANDLE hFile = CreateFileW(lockPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    CloseHandle(hFile);
    return true;
}

/**
 * @brief Delete the lock file.
 *
 * Called during normal cleanup after the sandboxed command completes.
 *
 * @param workspace  Workspace directory path
 * @param sid        Sandbox SID
 * @return true on success, false on failure
 */
bool deleteLockFile(PCWSTR workspace, PSID sid) {
    WCHAR lockPath[MAX_PATH];
    getLockFilePath(workspace, sid, lockPath, MAX_PATH);
    return DeleteFileW(lockPath) != FALSE;
}

/**
 * @brief Check whether a sandbox SID is still active (its lock file is fresh).
 *
 * Compares the lock file's last-write time against the current time.
 * If the file is missing or older than LOCK_EXPIRE_THRESHOLD_MS, the SID
 * is considered stale (the process that created it likely crashed).
 *
 * @param workspace  Workspace directory path
 * @param sid        Sandbox SID to check
 * @return true if the SID is active, false if stale or missing
 */
bool isSidActive(PCWSTR workspace, PSID sid) {
    WCHAR lockPath[MAX_PATH];
    getLockFilePath(workspace, sid, lockPath, MAX_PATH);

    WIN32_FILE_ATTRIBUTE_DATA fileData;
    if (!GetFileAttributesExW(lockPath, GetFileExInfoStandard, &fileData)) {
        return false;
    }

    FILETIME now;
    GetSystemTimeAsFileTime(&now);

    ULONGLONG nowLL = ((ULONGLONG)now.dwHighDateTime << 32) | now.dwLowDateTime;
    ULONGLONG fileLL = ((ULONGLONG)fileData.ftLastWriteTime.dwHighDateTime << 32) |
                       fileData.ftLastWriteTime.dwLowDateTime;

    ULONGLONG diffMs = (nowLL - fileLL) / 10000;
    return diffMs <= LOCK_EXPIRE_THRESHOLD_MS;
}

/**
 * @brief Heartbeat thread procedure.
 *
 * Periodically updates the lock file timestamp for each workspace to indicate
 * that the sandbox process is still running. If the process crashes, the lock
 * file will go stale and a subsequent sandbox invocation will clean up the ACE.
 *
 * @param lpParameter  Pointer to std::vector<std::pair<std::wstring, PSID>>
 * @return Always 0
 */
DWORD WINAPI LockUpdateThreadProc(LPVOID lpParameter) {
    std::vector<std::pair<std::wstring, PSID>>* workspaces =
        (std::vector<std::pair<std::wstring, PSID>>*)lpParameter;

    while (true) {
        DWORD waitResult = WaitForSingleObject(GetCurrentThread(), LOCK_UPDATE_INTERVAL_MS);
        if (waitResult == WAIT_OBJECT_0) {
            break;
        }

        for (const auto& pair : *workspaces) {
            updateLockFile(pair.first.c_str(), pair.second);
        }
    }

    return 0;
}

/**
 * @brief Check whether a DACL already contains an explicit GENERIC_WRITE
 *        allow-ACE for the given SID.
 *
 * @param dacl  DACL to inspect
 * @param sid   SID to search for
 * @return true if an allow-ACE with GENERIC_WRITE exists for the SID
 */
bool hasExplicitAllowWrite(PACL dacl, PSID sid) {
    if (!dacl) return false;
    for (DWORD i = 0; i < dacl->AceCount; i++) {
        ACE_HEADER* ace = NULL;
        if (!GetAce(dacl, i, (void**)&ace)) continue;
        if (ace->AceType != ACCESS_ALLOWED_ACE_TYPE &&
            ace->AceType != ACCESS_ALLOWED_CALLBACK_ACE_TYPE)
            continue;
        PSID aceSid = (ace->AceType == ACCESS_ALLOWED_ACE_TYPE)
            ? (PSID)&((ACCESS_ALLOWED_ACE*)ace)->SidStart
            : (PSID)&((ACCESS_ALLOWED_CALLBACK_ACE*)ace)->SidStart;
        if (!EqualSid(aceSid, sid)) continue;
        ACCESS_MASK mask = (ace->AceType == ACCESS_ALLOWED_ACE_TYPE)
            ? ((ACCESS_ALLOWED_ACE*)ace)->Mask
            : ((ACCESS_ALLOWED_CALLBACK_ACE*)ace)->Mask;
        if (mask & GENERIC_WRITE) return true;
    }
    return false;
}

/**
 * @brief Grant write access for a SID on a workspace directory.
 *
 * Performs two steps:
 *   1. Remove stale ("zombie") sandbox SIDs from the DACL — these are ACEs
 *      left by previous sandbox invocations that crashed before cleanup.
 *      A SID is considered stale if it is a sandbox SID, is not the current
 *      SID, and its lock file has expired.
 *   2. Add a GENERIC_WRITE | GENERIC_EXECUTE | DELETE ACE for the current SID if
 *      one does not already exist.
 *
 * The ACE is inherited by all files and subdirectories within the workspace.
 *
 * @param workspace  Workspace directory path
 * @param sid        Sandbox SID to grant write access to
 * @return true on success, false on failure
 */

bool ensureWorkspaceWriteAcl(PCWSTR workspace, PSID sid) {
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD err = GetNamedSecurityInfoW(
        (LPWSTR)workspace, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, &dacl, NULL, &sd);
    if (err != ERROR_SUCCESS) return false;

    // --- Step 1: Remove zombie sandbox SIDs (stale ACEs from crashed processes) ---
    DWORD keepCount = 0;
    for (DWORD i = 0; i < dacl->AceCount; i++) {
        ACE_HEADER* ace = NULL;
        if (!GetAce(dacl, i, (void**)&ace)) continue;
        if (ace->AceType != ACCESS_ALLOWED_ACE_TYPE &&
            ace->AceType != ACCESS_ALLOWED_CALLBACK_ACE_TYPE) {
            keepCount++; continue;
        }
        PSID aceSid = (ace->AceType == ACCESS_ALLOWED_ACE_TYPE)
            ? (PSID)&((ACCESS_ALLOWED_ACE*)ace)->SidStart
            : (PSID)&((ACCESS_ALLOWED_CALLBACK_ACE*)ace)->SidStart;
        // Keep non-sandbox SIDs, the current SID, and active sandbox SIDs
        if (!isSandboxSid(aceSid) || EqualSid(aceSid, sid) || isSidActive(workspace, aceSid)) {
            keepCount++;
        }
    }

    // Rebuild DACL without zombie SIDs if any were found
    PACL cleanedDacl = NULL;
    if (keepCount < dacl->AceCount) {
        DWORD newSize = sizeof(ACL);
        for (DWORD i = 0; i < dacl->AceCount; i++) {
            ACE_HEADER* ace = NULL;
            if (!GetAce(dacl, i, (void**)&ace)) continue;
            newSize += ace->AceSize;
        }
        cleanedDacl = (PACL)LocalAlloc(LPTR, newSize);
        if (cleanedDacl) {
            InitializeAcl(cleanedDacl, newSize, ACL_REVISION);
            for (DWORD i = 0; i < dacl->AceCount; i++) {
                ACE_HEADER* ace = NULL;
                if (!GetAce(dacl, i, (void**)&ace)) continue;
                if (ace->AceType != ACCESS_ALLOWED_ACE_TYPE &&
                    ace->AceType != ACCESS_ALLOWED_CALLBACK_ACE_TYPE) {
                    // Keep non-allow ACEs as-is
                    AddAce(cleanedDacl, ACL_REVISION, MAXDWORD, ace, ace->AceSize);
                    continue;
                }
                PSID aceSid = (ace->AceType == ACCESS_ALLOWED_ACE_TYPE)
                    ? (PSID)&((ACCESS_ALLOWED_ACE*)ace)->SidStart
                    : (PSID)&((ACCESS_ALLOWED_CALLBACK_ACE*)ace)->SidStart;
                // Keep non-sandbox SIDs, current SID, and active sandbox SIDs
                if (!isSandboxSid(aceSid) || EqualSid(aceSid, sid) || isSidActive(workspace, aceSid)) {
                    AddAce(cleanedDacl, ACL_REVISION, MAXDWORD, ace, ace->AceSize);
                }
            }
            dacl = cleanedDacl;
        }
    }

    // --- Step 2: Add write ACE for the current SID (if not already present) ---
    if (!hasExplicitAllowWrite(dacl, sid)) {
        EXPLICIT_ACCESSW ea = { 0 };
        // GENERIC_WRITE covers file creation/modification but NOT deletion.
        // DELETE is required for DeleteFileW / RemoveDirectoryW to work.
        ea.grfAccessPermissions = GENERIC_WRITE | GENERIC_EXECUTE | DELETE;
        ea.grfAccessMode = GRANT_ACCESS;
        ea.grfInheritance = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea.Trustee.ptstrName = (LPWSTR)sid;

        PACL newDacl = NULL;
        err = SetEntriesInAclW(1, &ea, dacl, &newDacl);
        if (err == ERROR_SUCCESS && newDacl) {
            err = SetNamedSecurityInfoW(
                (LPWSTR)workspace, SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                NULL, NULL, newDacl, NULL);
            LocalFree(newDacl);
        }
    }

    if (cleanedDacl) LocalFree(cleanedDacl);
    LocalFree(sd);
    return err == ERROR_SUCCESS;
}

/**
 * @brief Remove the sandbox SID's write ACE from a workspace directory's DACL.
 *
 * Rebuilds the DACL without any ACE matching the given SID, then applies it
 * back to the directory. Called during cleanup after the command completes.
 *
 * @param workspace  Workspace directory path
 * @param sid        Sandbox SID whose ACE should be removed
 * @return true on success, false on failure
 */
bool removeWorkspaceWriteAcl(PCWSTR workspace, PSID sid) {
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD err = GetNamedSecurityInfoW(
        (LPWSTR)workspace, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, &dacl, NULL, &sd);
    if (err != ERROR_SUCCESS || !dacl) { LocalFree(sd); return false; }

    // Count ACEs that are NOT owned by the target SID (to keep)
    DWORD keepCount = 0;
    for (DWORD i = 0; i < dacl->AceCount; i++) {
        ACE_HEADER* ace = NULL;
        if (!GetAce(dacl, i, (void**)&ace)) continue;
        PSID aceSid = NULL;
        if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE)
            aceSid = (PSID)&((ACCESS_ALLOWED_ACE*)ace)->SidStart;
        else if (ace->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE)
            aceSid = (PSID)&((ACCESS_ALLOWED_CALLBACK_ACE*)ace)->SidStart;
        else { keepCount++; continue; }
        if (!EqualSid(aceSid, sid)) keepCount++;
    }

    // Rebuild DACL without the target SID's ACEs
    DWORD newSize = sizeof(ACL) + keepCount * sizeof(ACCESS_ALLOWED_ACE);
    PACL newDacl = (PACL)LocalAlloc(LPTR, newSize);
    if (!newDacl) { LocalFree(sd); return false; }
    InitializeAcl(newDacl, newSize, ACL_REVISION);

    for (DWORD i = 0; i < dacl->AceCount; i++) {
        ACE_HEADER* ace = NULL;
        if (!GetAce(dacl, i, (void**)&ace)) continue;
        PSID aceSid = NULL;
        if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE)
            aceSid = (PSID)&((ACCESS_ALLOWED_ACE*)ace)->SidStart;
        else if (ace->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE)
            aceSid = (PSID)&((ACCESS_ALLOWED_CALLBACK_ACE*)ace)->SidStart;
        else { AddAce(newDacl, ACL_REVISION, MAXDWORD, ace, ace->AceSize); continue; }
        // Keep all ACEs except those matching the target SID
        if (!EqualSid(aceSid, sid))
            AddAce(newDacl, ACL_REVISION, MAXDWORD, ace, ace->AceSize);
    }

    err = SetNamedSecurityInfoW(
        (LPWSTR)workspace, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, newDacl, NULL);
    LocalFree(newDacl);
    LocalFree(sd);
    return err == ERROR_SUCCESS;
}
