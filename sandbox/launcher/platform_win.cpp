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
//   Restricted Token + ACL — Generate a random SID, grant it the workspace
//   grant mask (write + execute + delete, no DACL/owner tampering) on
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

/// Per-path DACL lock: how long to wait for a peer before failing closed. The
/// critical section is a DACL read-merge-write, and a first grant propagates
/// eagerly through the whole workspace tree (minutes on a large workspace), so
/// the budget has to cover a peer's full propagation.
#define ACL_LOCK_TIMEOUT_MS (30 * 60 * 1000)

/// Per-path DACL lock: retry interval while a peer holds the lock.
#define ACL_LOCK_RETRY_MS 50

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

/**
 * @brief Append every local drive root (e.g. "C:\\") to a path list.
 *
 * Used to declare the whole machine as read-only for the AppContainer
 * backend. Network drives are deliberately left out: declaring an unreachable
 * UNC root risks stalling process creation, and a confined process reading
 * local media covers the practical cases. The Restricted Token backend, which
 * does not restrict reads at all, therefore stays slightly wider here.
 *
 * @param out  List to append UTF-8 drive roots to
 */
static void appendDriveRoots(std::vector<std::string>& out) {
    WCHAR drives[512] = { 0 };
    if (!GetLogicalDriveStringsW(511, drives)) return;
    for (WCHAR* p = drives; *p; p += wcslen(p) + 1) {
        UINT type = GetDriveTypeW(p);
        if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE || type == DRIVE_CDROM) {
            out.push_back(wideToUtf8(p));
        }
    }
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
 * Only version, app_container, fs_read_write and fs_read_only are populated.
 * All other fields use schema defaults.
 *
 * Both path lists matter in normal operation: AppContainer is default-deny,
 * so without the read-only roots the child would lose read access to
 * everything outside the workspace — which is not the product semantic (only
 * *writes* are meant to be confined).
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
    writeU16(20);          // table_data_size = 20
    writeU16(4);   // field 0: version, at table+4
    writeU16(8);   // field 1: app_container, at table+8
    writeU16(0);   // field 2: not present
    writeU16(0);   // field 3: not present
    writeU16(0);   // field 4: not present
    writeU16(0);   // field 5: not present
    writeU16(0);   // field 6: not present
    writeU16(hasRW ? 12 : 0);  // field 7: fs_read_write, at table+12
    writeU16(hasRO ? 16 : 0);  // field 8: fs_read_only, at table+16

    // 3. Root Table (20 bytes)
    pad4();  // Align table start to 4 bytes
    size_t tablePos = outBuf.size();
    writeI32((int32_t)(tablePos - vtablePos));  // soffset to vtable

    size_t fieldVersionPos = outBuf.size();  // version string offset slot
    writeU32(0);  // placeholder

    outBuf.push_back(1);  // field 1: app_container = true
    pad4();  // align for the next uint32 field

    size_t fieldRWPos = outBuf.size();  // fs_read_write vector offset slot
    writeU32(0);  // placeholder

    size_t fieldROPos = outBuf.size();  // fs_read_only vector offset slot
    writeU32(0);  // placeholder

    // 4. Vectors of string offsets. Both are emitted: the workspace grants
    //    read/write while the read-only roots (drive roots, see the caller)
    //    keep everything else readable.
    struct VecInfo {
        size_t vecPos;
        std::vector<size_t> slotPos;
        std::vector<size_t> strPos;
    };
    auto emitVector = [&](const std::vector<std::string>& paths) -> VecInfo {
        VecInfo vi;
        pad4();
        vi.vecPos = outBuf.size();
        writeU32((uint32_t)paths.size());  // element count
        for (size_t i = 0; i < paths.size(); i++) {
            vi.slotPos.push_back(outBuf.size());
            writeU32(0);  // placeholder for string offset
        }
        for (size_t i = 0; i < paths.size(); i++) {
            pad4();
            vi.strPos.push_back(outBuf.size());
            writeU32((uint32_t)paths[i].length());
            outBuf.insert(outBuf.end(), paths[i].begin(), paths[i].end());
            outBuf.push_back(0);  // null terminator
            pad4();
        }
        return vi;
    };
    VecInfo rwInfo = { 0, {}, {} };
    VecInfo roInfo = { 0, {}, {} };
    if (hasRW) rwInfo = emitVector(readWritePaths);
    if (hasRO) roInfo = emitVector(readOnlyPaths);

    // 5. Version string "0.1.0"
    pad4();
    size_t versionPos = outBuf.size();
    const char* ver = "0.1.0";
    writeU32(5);  // length (excluding null)
    for (int i = 0; i < 5; i++) outBuf.push_back((uint8_t)ver[i]);
    outBuf.push_back(0);  // null terminator
    pad4();

    // 6. Fill in all offsets (relative to each offset's stored position)
    // Root table offset
    uint32_t rootOffset = (uint32_t)tablePos;
    memcpy(&outBuf[headerPos], &rootOffset, sizeof(rootOffset));

    // Version string offset (relative to fieldVersionPos)
    uint32_t verOffset = (uint32_t)(versionPos - fieldVersionPos);
    memcpy(&outBuf[fieldVersionPos], &verOffset, sizeof(verOffset));

    // Vector + string offsets
    auto fillVector = [&](const VecInfo& vi, size_t fieldPos) {
        if (vi.vecPos == 0) return;
        uint32_t vecOffset = (uint32_t)(vi.vecPos - fieldPos);
        memcpy(&outBuf[fieldPos], &vecOffset, sizeof(vecOffset));
        for (size_t i = 0; i < vi.slotPos.size(); i++) {
            uint32_t strOffset = (uint32_t)(vi.strPos[i] - vi.slotPos[i]);
            memcpy(&outBuf[vi.slotPos[i]], &strOffset, sizeof(strOffset));
        }
    };
    fillVector(rwInfo, fieldRWPos);
    fillVector(roInfo, fieldROPos);

    return true;
}

// ============================================================
//  Deterministic workspace capability identity
// ============================================================
//
// The write identity is a PURE FUNCTION of the canonical workspace path, so
// that the workspace ACE materializes once per workspace per machine instead
// of once per invocation:
//
//   - the workspace ACE is granted STANDING (never revoked), and
//   - ensureWorkspaceWriteAcl skips SetNamedSecurityInfoW entirely when the
//     exact ACE already stands.
//
// A per-invocation random identity cannot do this: every run would mint a new
// SID, so every run would need a fresh ACE (a full eager tree propagation)
// plus a revoke (a second one), and the leftovers could never be recognized
// as reusable. Measured on a 373,868-file workspace: grant ~233 s + revoke
// ~292 s per command.

/**
 * @brief Domain separator for the workspace identity derivation.
 *
 * The derivation is a pure function of the canonical workspace path, so any
 * two tools deriving an identity the same way would mint the SAME SID for the
 * same directory — and one tool's cleanup could then revoke the other's
 * standing grant. A product-specific domain keeps this product's identity
 * space disjoint from every other derivation.
 */
static const char kWorkspaceIdentityDomain[] = "ai-sandbox-workspace";

/**
 * @brief Resolve a path to its canonical final form.
 *
 * Opens the directory (FILE_FLAG_BACKUP_SEMANTICS, no access rights requested)
 * and asks the filesystem for the final path, which resolves junctions and
 * symlinks and normalizes case. Falls back to GetFullPathNameW when the handle
 * cannot be opened, so derivation never fails on a merely unusual path.
 *
 * Deriving from the CANONICAL path is what makes two spellings of one
 * workspace converge on one identity; an as-spelled path would mint a second
 * identity for the same directory and re-propagate its tree.
 *
 * @param path  Input path (may be relative)
 * @param out   Receives the canonical path (without the \\?\ prefix)
 * @return true on success
 */
static bool canonicalizePath(PCWSTR path, std::wstring& out) {
    HANDLE h = CreateFileW(path, 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD need = GetFinalPathNameByHandleW(h, NULL, 0,
                                               FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (need > 0) {
            std::wstring buf(need, L'\0');
            DWORD written = GetFinalPathNameByHandleW(h, &buf[0], need,
                                                      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            CloseHandle(h);
            if (written > 0 && written < need) {
                buf.resize(written);
                // The DOS-volume form is prefixed with \\?\ — strip it so the
                // derivation input matches the plain spelling callers use.
                if (buf.compare(0, 4, L"\\\\?\\") == 0) buf.erase(0, 4);
                out.assign(buf);
                return true;
            }
        } else {
            CloseHandle(h);
        }
    }

    DWORD required = GetFullPathNameW(path, 0, NULL, NULL);
    if (required == 0) return false;
    std::wstring buf(required, L'\0');
    DWORD written = GetFullPathNameW(path, required, &buf[0], NULL);
    if (written == 0 || written >= required) return false;
    buf.resize(written);
    out.assign(buf);
    return true;
}

/**
 * @brief SHA-256 over the domain-separated canonical workspace path.
 *
 * @param canonicalWorkspace  Canonical workspace path
 * @param out                 Receives the 32-byte digest
 * @return true on success
 */
static bool workspaceDigest(PCWSTR canonicalWorkspace, BYTE out[32]) {
    std::string utf8 = wideToUtf8(canonicalWorkspace);
    if (utf8.empty()) return false;

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return false;

    HCRYPTHASH hHash = 0;
    BOOL ok = CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    if (ok) {
        // sizeof() includes the terminating NUL, which is part of the domain.
        ok = CryptHashData(hHash, (const BYTE*)kWorkspaceIdentityDomain,
                           (DWORD)sizeof(kWorkspaceIdentityDomain), 0)
          && CryptHashData(hHash, (const BYTE*)utf8.data(), (DWORD)utf8.size(), 0);
    }

    DWORD len = 32;
    if (ok) ok = CryptGetHashParam(hHash, HP_HASHVAL, out, &len, 0);
    if (hHash) CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return ok != FALSE && len == 32;
}

/**
 * @brief Derive the workspace's deterministic capability SID (S-1-4-x-y).
 *
 * The SID is a pure function of the canonical workspace path, so every
 * confined execution of the same workspace — across sessions, process
 * restarts, and calls — carries the SAME write SID. That is what lets the
 * workspace ACE be granted once per workspace per machine and then reused:
 * the exact-ACE skip in ensureWorkspaceWriteAcl reduces every later provision
 * to a single DACL read instead of a full-tree re-propagation.
 *
 * Authority 4 (SECURITY_NON_UNIQUE_AUTHORITY) with two 30-bit sub-authorities
 * is the shape used for locally minted capability SIDs. It is deliberately
 * distinct from the legacy random S-1-5-10-* namespace, so the zombie sweep
 * still recognizes and reclaims ACEs left by older builds, while a workspace
 * capability SID is never treated as stale — it is a standing grant by design.
 *
 * @param workspace  Workspace directory path (canonicalized internally)
 * @param ppSid      Receives the allocated SID (caller must LocalFree)
 * @return true on success
 */
bool deriveWorkspaceSid(PCWSTR workspace, PSID* ppSid) {
    std::wstring canonical;
    if (!canonicalizePath(workspace, canonical)) return false;

    BYTE digest[32];
    if (!workspaceDigest(canonical.c_str(), digest)) return false;

    // Little-endian read of the first two words, folded into 30-bit
    // sub-authorities (the range S-1-4-x-y carries without overflow).
    DWORD first = (DWORD)digest[0] | ((DWORD)digest[1] << 8) |
                  ((DWORD)digest[2] << 16) | ((DWORD)digest[3] << 24);
    DWORD second = (DWORD)digest[4] | ((DWORD)digest[5] << 8) |
                   ((DWORD)digest[6] << 16) | ((DWORD)digest[7] << 24);
    first = (first % 0x3FFFFFFF) + 1;
    second = (second % 0x3FFFFFFF) + 1;

    WCHAR sz[64];
    _snwprintf_s(sz, _TRUNCATE, L"S-1-4-%lu-%lu", first, second);
    return ConvertStringSidToSidW(sz, ppSid) != FALSE;
}

/**
 * @brief Check whether a SID is a workspace capability SID (S-1-4-x-y).
 *
 * Such a SID names a STANDING grant (the cross-session reuse cache), so the
 * zombie sweep must never reclaim its ACE: doing so would force the next
 * invocation to re-propagate the whole workspace tree.
 *
 * @param sid  SID to check (may be NULL)
 * @return true if the SID is in the workspace capability namespace
 */
bool isWorkspaceCapabilitySid(PSID sid) {
    if (!sid) return false;
    SID_IDENTIFIER_AUTHORITY* auth = GetSidIdentifierAuthority(sid);
    if (auth->Value[5] != 4) return false;
    return *GetSidSubAuthorityCount(sid) == 2;
}

// ============================================================
//  AppContainer profile helpers (required before CreateProcessInSandbox
//  because the `identity` parameter must match a registered profile)
// ============================================================

#include <userenv.h>
#pragma comment(lib, "userenv.lib")  // for CreateAppContainerProfile / DeleteAppContainerProfile

/**
 * @brief Register the AppContainer profile for `identity` for this run.
 *
 * Registration is required before Experimental_CreateProcessInSandbox will
 * accept the identity; otherwise the engine may fail with
 * ERROR_CALL_NOT_IMPLEMENTED.
 *
 * A name collision (or a profile left behind by a crashed launcher) is
 * reported as FAILURE rather than accepted: the engine rejects a
 * re-registered identity outright (ERROR_ALREADY_EXISTS, measured even after
 * DeleteAppContainerProfile released the profile), so accepting it here would
 * only waste a doomed engine call and turn a clean backend fallback into a
 * confusing failure. With a fresh random name per run a collision is not
 * expected in practice.
 *
 * @param identity  Profile name (wide)
 * @return true when this call freshly registered the profile
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
    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
        fwprintf(stderr,
                 L"sandbox: [diagnostic] AppContainer profile \"%s\" already registered; "
                 L"the engine rejects a reused identity, falling back\n", identity);
        if (unusedSid) FreeSid(unusedSid);
        return false;
    }

    if (SUCCEEDED(hr)) {
        if (unusedSid) FreeSid(unusedSid);
        return true;
    }
    fwprintf(stderr, L"sandbox: [diagnostic] CreateAppContainerProfile(\"%s\") hr=0x%08X\n",
             identity, (UINT32)hr);
    if (unusedSid) FreeSid(unusedSid);
    return false;
}

/**
 * @brief Build a unique AppContainer profile name for this run.
 *
 * The name MUST be fresh every run, and this is a hard constraint of the
 * engine rather than a style choice: `Experimental_CreateProcessInSandbox`
 * fails with ERROR_ALREADY_EXISTS for any identity whose profile was ever
 * registered, even after the profile has been deleted again (measured: a
 * second run with the same name fails, a fresh name succeeds). A workspace
 * derived name would therefore work exactly once and then demote every later
 * run to the Restricted Token backend.
 *
 * The consequence is structural: an AppContainer identity cannot be reused,
 * so its derived SID changes every run, so its workspace ACE cannot be granted
 * standing — every AppContainer invocation pays an eager full-tree grant AND
 * an eager full-tree revoke. That is why the reusable-grant fast path belongs
 * to the Restricted Token backend (see deriveWorkspaceSid).
 *
 * Format: `AISandbox-<pid>-<16 hex digits>` — hyphen-separated, as
 * AppContainer profile names reject some punctuation, and short enough to sit
 * well inside the 64-character limit.
 *
 * @param out  Receives the generated profile name
 * @return true on success, false if the RNG is unavailable
 */
static bool makeAppContainerIdentity(std::wstring& out) {
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return false;
    DWORD r[2] = { 0, 0 };
    BOOL ok = CryptGenRandom(hProv, sizeof(r), (BYTE*)r);
    CryptReleaseContext(hProv, 0);
    if (!ok) return false;

    WCHAR buf[64];
    _snwprintf_s(buf, _TRUNCATE, L"AISandbox-%lu-%08lX%08lX",
                 GetCurrentProcessId(), r[0], r[1]);
    out.assign(buf);
    return true;
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
 * @brief Create a Job Object with KILL_ON_JOB_CLOSE so the sandboxed child
 *        and its descendants die when the launcher exits.
 *
 * @return Job handle, or NULL on failure (protection is best-effort)
 */
static HANDLE createKillOnCloseJob() {
    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (!hJob) return NULL;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo = { 0 };
    jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                                 &jobInfo, sizeof(jobInfo))) {
        fwprintf(stderr, L"sandbox: job object setup failed (%lu)\n", GetLastError());
        CloseHandle(hJob);
        return NULL;
    }
    return hJob;
}

/**
 * @brief Try running the command via Experimental_CreateProcessInSandbox.
 *
 * Probes for processmodel.dll and the experimental API. If unavailable or
 * the call fails, returns false to signal the caller to fall back to the
 * Restricted Token approach.
 *
 * The exit code is reported through an out parameter — it must never share
 * a channel with the "should fall back" signal: child processes legitimately
 * exit with 0xFFFFFFFF (-1), which would otherwise trigger a second run of
 * the same command via the fallback backend.
 *
 * @param cmdLine    Full command line (shell + args + user command)
 * @param workingDir Working directory for the child process
 * @param wWorkspaces Workspace directories (for fs_read_write / fs_read_only)
 * @param readOnly   If true, workspaces are read-only
 * @param exitCodeOut Receives the child's exit code when true is returned
 * @return true if the command was executed via the sandbox API, false if the
 *         caller should fall back
 */
static bool ensureWorkspaceWriteAcl(PCWSTR workspace, PSID sid);
static bool removeWorkspaceWriteAcl(PCWSTR workspace, PSID sid);

static bool runWithSandboxApi(
    const std::wstring& cmdLine,
    const std::wstring& workingDir,
    const std::vector<std::wstring>& wWorkspaces,
    bool readOnly,
    int* exitCodeOut
) {
    // 1. Load processmodel.dll from System32
    HMODULE hMod = LoadLibraryExW(L"processmodel.dll", NULL,
                                  LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!hMod) return false;

    auto pfnCreate = (PFN_Experimental_CreateProcessInSandbox)
        GetProcAddress(hMod, "Experimental_CreateProcessInSandbox");
    if (!pfnCreate) {
        FreeLibrary(hMod);
        return false;
    }

    // 2. Build the FlatBuffer SandboxSpec
    //    AppContainer is default-deny for reads as well as writes, so the
    //    drive roots are declared read-only to keep the product semantic:
    //    readable everywhere, writable only inside the workspace. This is
    //    also what lets the default shell work — without a readable C:\,
    //    PowerShell's FileSystem provider fails to initialise, relative paths
    //    resolve to C:\ and every relative command is refused.
    std::vector<std::string> rwPaths, roPaths;
    if (!readOnly) {
        for (const auto& ws : wWorkspaces)
            rwPaths.push_back(wideToUtf8(ws));
    } else {
        for (const auto& ws : wWorkspaces)
            roPaths.push_back(wideToUtf8(ws));
    }
    appendDriveRoots(roPaths);

    std::vector<uint8_t> specBuf;
    if (!buildSandboxSpec(rwPaths, roPaths, specBuf)) {
        FreeLibrary(hMod);
        return false;
    }

    // 3. Register a fresh AppContainer profile for this run. A fixed identity
    //    cannot be reused: the engine fails with ERROR_ALREADY_EXISTS as soon
    //    as the profile exists, which silently demotes every run after the
    //    first one to the Restricted Token backend. Deleted again below.
    std::wstring identity;
    if (!makeAppContainerIdentity(identity)) {
        FreeLibrary(hMod);
        return false;
    }
    if (!ensureAppContainerProfile(identity.c_str())) {
        // profile registration failed → API won't accept the identity, fall back
        FreeLibrary(hMod);
        return false;
    }

    // 3b. Grant the AppContainer SID the workspace grant mask on every
    //     workspace. The engine's fs_read_write binding only lets the child
    //     *create* new files; modifying or deleting a file that already
    //     exists requires the file's own DACL to grant the AppContainer SID,
    //     which typical host ACLs do not (observed on GitHub runners:
    //     BUILTIN\Users:(RX) only — every pre-existing-file case failed with
    //     "Access is denied"). Same grant shape as the Restricted Token
    //     backend; the ACEs are removed again during cleanup below. This
    //     also makes each run's SID single-purpose, so a leftover ACE from a
    //     killed launcher is inert.
    std::vector<std::wstring> grantedWorkspaces;
    PSID appContainerSid = NULL;
    HRESULT sidHr = DeriveAppContainerSidFromAppContainerName(identity.c_str(),
                                                              &appContainerSid);
    if (FAILED(sidHr) || !appContainerSid) {
        fwprintf(stderr, L"sandbox: cannot derive AppContainer SID (0x%08X)\n",
                 (unsigned)sidHr);
        DeleteAppContainerProfile(identity.c_str());
        FreeLibrary(hMod);
        return false;
    }
    if (!readOnly) {
        for (const auto& ws : wWorkspaces) {
            if (ensureWorkspaceWriteAcl(ws.c_str(), appContainerSid)) {
                grantedWorkspaces.push_back(ws);
            }
        }
    }
    auto cleanupAppContainer = [&]() {
        for (const auto& ws : grantedWorkspaces)
            removeWorkspaceWriteAcl(ws.c_str(), appContainerSid);
        LocalFree(appContainerSid);
        DeleteAppContainerProfile(identity.c_str());
    };

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
    if (!cmdCopy) {
        cleanupAppContainer();
        FreeLibrary(hMod);
        return false;
    }
    wcscpy_s(cmdCopy, cmdLine.size() + 1, cmdLine.c_str());

    // 6. Create Job Object (ensures child is killed if parent dies)
    HANDLE hJob = createKillOnCloseJob();

    // 7. Launch the sandboxed process
    // Clear the last error first: the engine does not always set one, and a
    // stale value from CreateAppContainerProfile would be misread as the
    // engine's own failure code.
    SetLastError(ERROR_SUCCESS);
    PROCESS_INFORMATION pi = {};
    BOOL ok = pfnCreate(
        NULL,               // applicationName (resolve from commandLine)
        cmdCopy,            // commandLine
        NULL,               // processAttributes (reserved)
        NULL,               // threadAttributes (reserved)
        FALSE,              // inheritHandles (must be FALSE)
        CREATE_SUSPENDED,   // resumed below, after the job assignment
        NULL,               // environment (inherit parent's)
        workingDir.c_str(),
        &si,
        identity.c_str(),
        specBuf.data(),
        (DWORD)specBuf.size(),
        &pi
    );

    LocalFree(cmdCopy);

    if (!ok) {
        // API call failed — fall back to Restricted Token. Say so: a silent
        // fallback hides a weaker backend (no read confinement) behind a
        // success exit code.
        DWORD apiErr = GetLastError();
        fwprintf(stderr,
                 L"sandbox: [diagnostic] Experimental_CreateProcessInSandbox failed "
                 L"(err=%lu); falling back to the restricted-token backend\n", apiErr);
        cleanupAppContainer();
        if (hJob) CloseHandle(hJob);
        FreeLibrary(hMod);
        return false;
    }

    FreeLibrary(hMod);

    // 8. Assign to the job while the child is suspended so no grandchild can
    // be spawned outside the job's kill-on-close protection, then resume.
    // Both steps are best-effort: on failure the child only loses
    // kill-on-parent-exit protection.
    if (hJob && !AssignProcessToJobObject(hJob, pi.hProcess)) {
        fwprintf(stderr, L"sandbox: job assignment failed (%lu)\n", GetLastError());
    }
    if (pi.hThread) ResumeThread(pi.hThread);

    // On wait failure, still report the command as executed: re-running it
    // via the fallback backend would double-execute the command.
    DWORD exitCode = (DWORD)-1;
    if (WaitForSingleObject(pi.hProcess, INFINITE) == WAIT_OBJECT_0) {
        if (!GetExitCodeProcess(pi.hProcess, &exitCode)) {
            exitCode = (DWORD)-1;
        }
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (hJob) CloseHandle(hJob);

    // Drop this run's ACEs and profile: the engine rejects an identity whose
    // profile is still registered, so leaving either behind would break the
    // next run.
    cleanupAppContainer();

    *exitCodeOut = (int)exitCode;
    return true;
}

// ============================================================
//  Forward declarations
// ============================================================
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

/**
 * @brief Stop the heartbeat thread and release the per-run bookkeeping.
 *
 * Shared by every failure path after step 3 (ACL + lock setup) and by the
 * normal-exit cleanup. Must run before the process exits: the heartbeat
 * thread touches the lock files, so it is terminated first.
 *
 * The workspace ACE is deliberately NOT revoked. It is the STANDING grant —
 * the cross-run reuse cache keyed by the workspace's deterministic SID — and
 * revoking it would force the next invocation to re-propagate the whole
 * workspace tree (an eager SetNamedSecurityInfoW walk over every descendant,
 * which dominates the cost of large workspaces). Leaving it in place is safe:
 * the SID grants nothing on its own, and only a token minted for this
 * workspace carries it as a restricting SID.
 *
 * @param hHeartbeatThread  Heartbeat thread handle (may be NULL)
 * @param wWorkspaces       Workspace directories (wide)
 * @param workspaceSid      Workspace capability SID whose lock files are removed
 */
static void cleanupWorkspaceGrants(
    HANDLE hHeartbeatThread,
    const std::vector<std::wstring>& wWorkspaces,
    PSID workspaceSid
) {
    if (hHeartbeatThread) {
        TerminateThread(hHeartbeatThread, 0);
        CloseHandle(hHeartbeatThread);
    }
    if (CLEANUP_AFTER_EACH_COMMAND) {
        for (const auto& ws : wWorkspaces) {
            deleteLockFile(ws.c_str(), workspaceSid);
        }
    }
}

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

    // Ensure all workspace directories exist (create if missing) and normalize
    // every path, so ACL, lock files, the child working directory and the
    // sandbox API spec all reference the same directory. (Symlink/junction
    // final-name resolution is deliberately not attempted here.)
    for (auto& ws : wWorkspaces) {
        CreateDirectoryW(ws.c_str(), NULL);
        DWORD required = GetFullPathNameW(ws.c_str(), 0, NULL, NULL);
        if (required > 0) {
            std::wstring full(required, L'\0');
            DWORD written = GetFullPathNameW(ws.c_str(), required, &full[0], NULL);
            if (written > 0 && written < required) {
                full.resize(written);
                ws = std::move(full);
            }
        }
    }

    // --- Select command shell ---
    std::wstring shell = utf8ToWide(cfg.shell);
    std::wstring shellPath;
    std::wstring shellArgs;
    if (shell.empty() || _wcsicmp(shell.c_str(), L"powershell") == 0 ||
        _wcsicmp(shell.c_str(), L"ps") == 0) {
        // Default shell is PowerShell (matches config.h documentation).
        shellPath = L"powershell.exe";
        shellArgs = L"-NoProfile -NonInteractive -Command ";
    } else if (_wcsicmp(shell.c_str(), L"cmd") == 0) {
        shellPath = L"cmd.exe";
        shellArgs = L"/c ";
    } else {
        fwprintf(stderr, L"sandbox: unsupported shell '%s' (Windows supports: powershell, cmd)\n",
                 shell.c_str());
        return 1;
    }

    // --- Build command line: <shell> <args> <command> ---
    std::wstring cmdLine = shellPath + L" " + shellArgs + wCommand;

    // --- Backend selection: the Restricted Token backend is the ONLY active
    //     backend. ---
    //
    // The AppContainer backend (Experimental_CreateProcessInSandbox, i.e. the
    // mxc BaseContainer tier) is RETIRED from selection. It is not a
    // performance-tuning choice but a structural incompatibility:
    //
    //   - the engine rejects an identity that was ever registered
    //     (ERROR_ALREADY_EXISTS, measured on a profile that had already been
    //     deleted), so a profile name must be fresh every run;
    //   - the derived AppContainer SID follows the name, so the SID changes
    //     every run;
    //   - a per-run SID cannot carry a STANDING workspace ACE, so every
    //     invocation pays an eager full-tree grant AND an eager full-tree
    //     revoke — the exact cost the deterministic workspace SID exists to
    //     remove (see deriveWorkspaceSid).
    //
    // Its only remaining advantage is read-side default-deny, which this
    // product does not promise ("reads unaffected") and which cannot be had
    // without the same wholesale host-DACL mutation. The implementation is
    // kept intact for reference and for a future engine revision that accepts
    // a reused identity; set SANDBOX_FORCE_APPCONTAINER=1 to exercise it.
    // SANDBOX_FORCE_RESTRICTED_TOKEN=1 still means "do not attempt
    // AppContainer" and therefore wins when both are set.
    {
        wchar_t flag[8];
        bool forceRestrictedToken =
            GetEnvironmentVariableW(L"SANDBOX_FORCE_RESTRICTED_TOKEN", flag, 8) > 0;
        bool forceAppContainer =
            GetEnvironmentVariableW(L"SANDBOX_FORCE_APPCONTAINER", flag, 8) > 0;

        if (forceAppContainer && !forceRestrictedToken) {
            int sandboxExitCode = 0;
            if (runWithSandboxApi(cmdLine, wWorkspaces[0], wWorkspaces, cfg.readOnly,
                                  &sandboxExitCode)) {
                return sandboxExitCode;
            }
            // Engine unavailable or the call failed — fall through.
        }
    }

    // ================================================================
    //  Restricted Token + ACL backend (the active Windows backend)
    // ================================================================

    // --- 1. Open current process token for duplication ---
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken)) {
        fwprintf(stderr, L"sandbox: token error (%lu)\n", GetLastError());
        return 1;
    }

    // --- 2. Derive the workspace capability SID ---
    // Deterministic per canonical workspace path (deriveWorkspaceSid), so the
    // workspace ACE materializes once per workspace per machine and every
    // later invocation reuses it instead of re-propagating the tree. It doubles
    // as the token's restricting SID for workspace-write (step 4).
    //
    // In read-only mode the SID is deliberately NOT added to the restricting
    // list (step 4). The workspace ACE granted by an earlier workspace-write
    // period is STANDING and outlives that period, so leaving the SID in the
    // read-only list would let that stale grant satisfy the restricted write
    // check and re-open writes. A random per-run SID was inert in read-only
    // mode because it never had an ACE anywhere; a standing one is not.
    PSID workspaceSid = NULL;
    HANDLE hHeartbeatThread = NULL;
    std::vector<std::pair<std::wstring, PSID>> wsList;
    if (!deriveWorkspaceSid(wWorkspaces[0].c_str(), &workspaceSid)) {
        fwprintf(stderr, L"sandbox: workspace SID derivation failed\n");
        CloseHandle(hToken);
        return 1;
    }
    if (!cfg.readOnly) {
        // --- 3. Grant write access on each workspace dir + create lock files ---
        // Fail closed: without its ACE the workspace is unwritable and the
        // command can never succeed — abort instead of running with a
        // half-configured sandbox.
        for (const auto& ws : wWorkspaces) {
            if (!ensureWorkspaceWriteAcl(ws.c_str(), workspaceSid)) {
                fwprintf(stderr, L"sandbox: ACL setup failed for %s\n", ws.c_str());
                cleanupWorkspaceGrants(hHeartbeatThread, wWorkspaces, workspaceSid);
                LocalFree(workspaceSid);
                CloseHandle(hToken);
                return 1;
            }
            if (!createLockFile(ws.c_str(), workspaceSid)) {
                fwprintf(stderr, L"sandbox: cannot create lock file in %s\n", ws.c_str());
                cleanupWorkspaceGrants(hHeartbeatThread, wWorkspaces, workspaceSid);
                LocalFree(workspaceSid);
                CloseHandle(hToken);
                return 1;
            }
        }

        // --- 3.5 Start heartbeat thread for lock file maintenance ---
        for (const auto& ws : wWorkspaces) {
            wsList.emplace_back(ws, workspaceSid);
        }
        hHeartbeatThread = CreateThread(NULL, 0, LockUpdateThreadProc, &wsList, 0, NULL);
    }

    // --- 4. Create Restricted Token ---
    // WRITE_RESTRICTED consults restricting SIDs only for write-type accesses;
    // reads keep using the token's normal user SIDs.
    //
    // The restricting set is {workspace SID, logon SID, Everyone}. All three
    // are needed, for different reasons:
    //   - workspace SID gates workspace writes: a write there requires an ACE
    //     explicitly granting that random SID, which only the workspace has.
    //   - logon SID and Everyone gate *process startup*, not user data. With
    //     the restricting set narrowed to the workspace SID alone, process
    //     initialization fails for everything beyond cmd.exe (measured on
    //     Win11 24H2/25H2, builds 26100/26200: powershell.exe exits 0xC0000142
    //     STATUS_DLL_INIT_FAILED, where.exe and similar tools silently fail
    //     to run). Dropping either one still breaks powershell.exe; only the
    //     full set starts cleanly.
    // Writes outside the workspace stay denied as long as those SIDs hold no
    // write ACE on the target — the documented caveat is ACL-less volumes
    // (FAT/exFAT/network shares), where Everyone is implicitly granted; see
    // the README "known limitations" note.
    //
    // LUA_TOKEN must NOT be used here. It marks the caller's administrative
    // SIDs use-for-deny-only in the child's *normal* token, and a
    // WRITE_RESTRICTED token requires BOTH the normal check and the
    // restricted check to succeed for write-type accesses. On an elevated
    // caller (e.g. GitHub runners) whose files grant full control only to
    // Administrators + read to Users, the normal check then fails for any
    // operation on a file that predates the run — delete/overwrite inside
    // the workspace were denied even though the workspace SID's ACE granted
    // them and the restricted check passed. Write confinement is enforced by
    // the restricted check alone.
    PSID logonSid = NULL;
    PSID everyoneSid = NULL;
    {
        DWORD len = 0;
        GetTokenInformation(hToken, TokenGroups, NULL, 0, &len);
        if (len) {
            TOKEN_GROUPS* tg = (TOKEN_GROUPS*)LocalAlloc(LPTR, len);
            if (tg && GetTokenInformation(hToken, TokenGroups, tg, len, &len)) {
                for (DWORD i = 0; i < tg->GroupCount; i++) {
                    if (tg->Groups[i].Attributes & SE_GROUP_LOGON_ID) {
                        DWORD sidLen = GetLengthSid(tg->Groups[i].Sid);
                        logonSid = (PSID)LocalAlloc(LPTR, sidLen);
                        if (logonSid) CopySid(sidLen, logonSid, tg->Groups[i].Sid);
                        break;
                    }
                }
            }
            if (tg) LocalFree(tg);
        }
        everyoneSid = (PSID)LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
        if (everyoneSid) {
            DWORD evSidSize = SECURITY_MAX_SID_SIZE;
            if (!CreateWellKnownSid(WinWorldSid, NULL, everyoneSid, &evSidSize)) {
                LocalFree(everyoneSid);
                everyoneSid = NULL;
            }
        }
    }

    // Both SIDs are required for child process startup. If either is missing
    // the command may still run, but processes that need a full token
    // (powershell.exe and friends) will fail to initialize — say so instead
    // of degrading silently.
    if (!logonSid || !everyoneSid) {
        fwprintf(stderr,
                 L"sandbox: warning: logon/Everyone SID unavailable "
                 L"(logon=%d everyone=%d); some processes may fail to start\n",
                 logonSid != NULL, everyoneSid != NULL);
    }

    // The restricting set gates write-class accesses only (WRITE_RESTRICTED):
    // a write must clear both the normal check and this one. The logon SID and
    // Everyone are keep-alive invariants — without them child initialization
    // fails — so they are present in both modes. The workspace capability SID
    // is present ONLY in workspace-write: its ACE is standing, so carrying it
    // under read-only would let a grant left over from an earlier
    // workspace-write period satisfy the restricted check.
    SID_AND_ATTRIBUTES restrictingSids[3] = {};
    DWORD numRestricting = 0;
    if (!cfg.readOnly) restrictingSids[numRestricting++].Sid = workspaceSid;
    if (logonSid)    restrictingSids[numRestricting++].Sid = logonSid;
    if (everyoneSid) restrictingSids[numRestricting++].Sid = everyoneSid;

    HANDLE hRestrictedToken = NULL;
    BOOL ok = CreateRestrictedToken(
        hToken,
        DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED,
        0, NULL,          0, NULL,
        numRestricting, restrictingSids,
        &hRestrictedToken
    );
    CloseHandle(hToken);
    LocalFree(logonSid);
    LocalFree(everyoneSid);

    if (!ok) {
        fwprintf(stderr, L"sandbox: CreateRestrictedToken (%lu)\n", GetLastError());
        if (!cfg.readOnly) cleanupWorkspaceGrants(hHeartbeatThread, wWorkspaces, workspaceSid);
        LocalFree(workspaceSid);
        return 1;
    }

    // --- 5. Create Job Object (ensures child is killed if parent dies) ---
    HANDLE hJob = createKillOnCloseJob();

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
        CREATE_SUSPENDED,  // resumed below, after the job assignment
        NULL,
        wWorkspaces[0].c_str(),  // Set working directory to first workspace
        &si, &pi
    );
    LocalFree(cmdCopy);

    if (!ok) {
        fwprintf(stderr, L"sandbox: CreateProcessAsUserW (%lu)\n", GetLastError());
        CloseHandle(hRestrictedToken);
        if (hJob) CloseHandle(hJob);
        if (!cfg.readOnly) cleanupWorkspaceGrants(hHeartbeatThread, wWorkspaces, workspaceSid);
        LocalFree(workspaceSid);
        return 1;
    }

    // Assign the child to the job while it is suspended so no grandchild can
    // be spawned outside the job's kill-on-close protection, then resume.
    // Best-effort: on failure the child only loses kill-on-parent-exit
    // protection.
    if (hJob && !AssignProcessToJobObject(hJob, pi.hProcess)) {
        fwprintf(stderr, L"sandbox: job assignment failed (%lu)\n", GetLastError());
    }
    if (pi.hThread) ResumeThread(pi.hThread);

    // Wait for the child process to finish
    DWORD exitCode = (DWORD)-1;
    if (WaitForSingleObject(pi.hProcess, INFINITE) == WAIT_OBJECT_0) {
        if (!GetExitCodeProcess(pi.hProcess, &exitCode)) {
            exitCode = (DWORD)-1;
        }
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    CloseHandle(hRestrictedToken);
    if (hJob) CloseHandle(hJob);

    // --- 8. Stop heartbeat thread and drop the per-run lock files. The
    //        workspace ACE is left standing (the cross-run reuse cache). ---
    if (!cfg.readOnly) {
        cleanupWorkspaceGrants(hHeartbeatThread, wWorkspaces, workspaceSid);
    }

    LocalFree(workspaceSid);
    return (int)exitCode;
}

} // namespace sandbox

// ============================================================
//  Helper functions
// ============================================================

/**
 * @brief Check whether a SID belongs to the legacy sandbox namespace (S-1-5-10-*).
 *
 * Older builds minted a random S-1-5-10-* SID per invocation and revoked its
 * ACE on exit. An ACE in this namespace that is not the current SID is
 * therefore residue from a build that crashed (or was killed) before cleanup,
 * and the sweep may reclaim it. The current workspace SID lives in a different
 * namespace on purpose — see deriveWorkspaceSid and isWorkspaceCapabilitySid.
 *
 * @param sid  SID to check (may be NULL)
 * @return true if the SID is in the legacy sandbox namespace, false otherwise
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
 * @brief Access mask the sandbox SID receives on workspace directories.
 *
 * Write + execute + delete + child deletion, with READ_CONTROL kept so
 * generic (GENERIC_WRITE / GENERIC_READ) requests map onto the mask.
 * WRITE_DAC / WRITE_OWNER stay excluded so a confined child cannot rewrite
 * DACLs or take ownership to escape the allowlist.
 */
static const ACCESS_MASK kWorkspaceGrantMask =
    (FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE | FILE_DELETE_CHILD) &
    ~(WRITE_DAC | WRITE_OWNER);

/**
 * @brief Check whether a DACL already contains an explicit allow-ACE covering
 *        the workspace grant mask for the given SID.
 *
 * @param dacl  DACL to inspect
 * @param sid   SID to search for
 * @return true if an allow-ACE for the SID covers kWorkspaceGrantMask
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
        if ((mask & kWorkspaceGrantMask) == kWorkspaceGrantMask) return true;
    }
    return false;
}

/**
 * @brief Per-path exclusive lock serializing DACL mutations on one workspace.
 *
 * The grant/revoke sequence is a read-merge-write of the directory's DACL and
 * is therefore not safe to run concurrently with itself: two invocations that
 * both read the DACL before either writes can lose each other's changes. The
 * lock is a real cross-PROCESS lock (LockFileEx on a lock file inside the
 * workspace) because the concurrent invocations are separate sandbox.exe
 * processes, not threads.
 *
 * It also removes the worst concurrency cost. Without it, N simultaneous first
 * commands on a workspace all observe "no ACE yet" and all call
 * SetNamedSecurityInfoW, each triggering its own eager full-tree propagation
 * over the same tree. With it, the first invocation propagates while the rest
 * wait, then find the exact ACE standing and take the O(1) skip.
 *
 * Acquisition is bounded: a peer's first grant legitimately takes minutes on a
 * large workspace, so the budget is generous, but a peer that died holding the
 * lock must not hang the sandbox forever. Failure to acquire is reported to the
 * caller, which fails closed rather than mutating the DACL unlocked.
 */
class AclPathLock {
public:
    AclPathLock() : handle_(INVALID_HANDLE_VALUE) {
        ZeroMemory(&overlapped_, sizeof(overlapped_));
    }

    ~AclPathLock() { release(); }

    AclPathLock(const AclPathLock&) = delete;
    AclPathLock& operator=(const AclPathLock&) = delete;

    /**
     * @brief Create/open the lock file and take an exclusive lock on it.
     * @param workspace  Workspace directory whose DACL will be mutated
     * @return true when the lock is held
     */
    bool acquire(PCWSTR workspace) {
        WCHAR lockDir[MAX_PATH];
        _snwprintf_s(lockDir, _TRUNCATE, L"%s\\.sandbox", workspace);
        CreateDirectoryW(lockDir, NULL);

        WCHAR lockPath[MAX_PATH];
        _snwprintf_s(lockPath, _TRUNCATE, L"%s\\acl.lock", lockDir);

        handle_ = CreateFileW(lockPath, GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
        if (handle_ == INVALID_HANDLE_VALUE) return false;

        // Zeroed OVERLAPPED means "lock byte 0"; retry rather than block so the
        // wait can be bounded. LOCKFILE_FAIL_IMMEDIATELY makes a held lock
        // return ERROR_LOCK_VIOLATION instead of blocking.
        const DWORD deadline = GetTickCount() + ACL_LOCK_TIMEOUT_MS;
        for (;;) {
            if (LockFileEx(handle_, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                           0, 1, 0, &overlapped_)) {
                return true;
            }
            if (GetLastError() != ERROR_LOCK_VIOLATION) break;
            if ((LONG)(GetTickCount() - deadline) >= 0) break;
            Sleep(ACL_LOCK_RETRY_MS);
        }

        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
        return false;
    }

    /** @brief Release the lock (idempotent). */
    void release() {
        if (handle_ == INVALID_HANDLE_VALUE) return;
        UnlockFileEx(handle_, 0, 1, 0, &overlapped_);
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }

private:
    HANDLE handle_;
    OVERLAPPED overlapped_;
};

/**
 * @brief Grant write access for a SID on a workspace directory.
 *
 * Performs two steps:
 *   1. Remove stale ("zombie") sandbox SIDs from the DACL — these are ACEs
 *      left by previous sandbox invocations that crashed before cleanup.
 *      A SID is considered stale if it is a legacy sandbox SID, is not the
 *      current SID, is not a standing workspace capability SID, and its lock
 *      file has expired.
 *   2. Add a kWorkspaceGrantMask ACE (write + execute + delete + child
 *      deletion, no WRITE_DAC/WRITE_OWNER) for the current SID if
 *      one does not already exist.
 *
 * The whole sequence runs under the per-path lock (see AclPathLock), and when
 * the DACL is already in its target state the apply is skipped entirely — the
 * ACE is a standing, deterministic grant, so that is the steady state.
 *
 * The ACE is inherited by all files and subdirectories within the workspace.
 *
 * @param workspace  Workspace directory path
 * @param sid        Sandbox SID to grant write access to
 * @return true on success, false on failure
 */

bool ensureWorkspaceWriteAcl(PCWSTR workspace, PSID sid) {
    // Serialize the whole read-decide-write sequence against peer sandbox
    // processes. Fail closed: mutating the DACL unlocked could lose a peer's
    // concurrent change, and a lock that cannot be taken means the state is
    // unknown.
    AclPathLock pathLock;
    if (!pathLock.acquire(workspace)) return false;
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
        // Keep non-sandbox SIDs, the current SID, active sandbox SIDs, and
        // workspace capability SIDs. The last clause is explicit on purpose: a
        // workspace capability SID is a STANDING grant (the cross-run reuse
        // cache) and must never be reclaimed as stale. Today isSandboxSid only
        // matches the legacy S-1-5-10-* namespace, which makes the clause
        // redundant — but anyone broadening that predicate (for example to also
        // recognize the AppContainer namespace, which the sweep currently
        // misses) would otherwise silently start deleting the cache and
        // re-introduce the full-tree re-propagation.
        if (!isSandboxSid(aceSid) || EqualSid(aceSid, sid) ||
            isWorkspaceCapabilitySid(aceSid) || isSidActive(workspace, aceSid)) {
            keepCount++;
        }
    }

    // --- Fast path: the DACL is already in its target state ---
    // The exact grant ACE stands and no zombie ACE needs reclaiming, so there
    // is nothing to write. This is the steady state from the second invocation
    // on, and it is the entire point of deriving the SID from the workspace:
    // SetNamedSecurityInfoW applies eager inheritance, so calling it would walk
    // and re-stamp every descendant (minutes on a large workspace) even though
    // the resulting DACL is byte-identical.
    bool exactStands = hasExplicitAllowWrite(dacl, sid);
    if (GetEnvironmentVariableW(L"SANDBOX_ACL_DIAG", NULL, 0) > 0) {
        WCHAR* sidStr = NULL;
        ConvertSidToStringSidW(sid, &sidStr);
        fwprintf(stderr, L"[acl-diag] sid=%s exact=%d keep=%lu/%lu\n",
                 sidStr ? sidStr : L"?", exactStands ? 1 : 0, keepCount, dacl->AceCount);
        if (sidStr) LocalFree(sidStr);
    }
    if (keepCount == dacl->AceCount && exactStands) {
        LocalFree(sd);
        return true;
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
                // Keep non-sandbox SIDs, the current SID, active sandbox SIDs,
                // and standing workspace capability SIDs (see step 1).
                if (!isSandboxSid(aceSid) || EqualSid(aceSid, sid) ||
                    isWorkspaceCapabilitySid(aceSid) || isSidActive(workspace, aceSid)) {
                    AddAce(cleanedDacl, ACL_REVISION, MAXDWORD, ace, ace->AceSize);
                }
            }
            dacl = cleanedDacl;
        }
    }

    // --- Step 2: Add write ACE for the current SID (if not already present) ---
    if (!hasExplicitAllowWrite(dacl, sid)) {
        EXPLICIT_ACCESSW ea = { 0 };
        // Explicit least-privilege grant: write + execute + delete + child
        // deletion, with READ_CONTROL kept so generic (GENERIC_WRITE/READ)
        // requests map onto the mask. WRITE_DAC / WRITE_OWNER stay excluded
        // so a confined child cannot rewrite DACLs or take ownership to
        // escape the allowlist (same grant shape as the deepseek-harness
        // windows-acl sandbox). DELETE is required for DeleteFileW /
        // RemoveDirectoryW; FILE_DELETE_CHILD covers child deletion and
        // renames regardless of the child's own DACL.
        ea.grfAccessPermissions = kWorkspaceGrantMask;
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
 * @brief Remove a capability SID's ACE from a directory's DACL.
 *
 * Used by the AppContainer backend, whose identity is fresh every run: there
 * the ACE is per-run state and must be revoked, or each invocation would leave
 * a dead entry behind. The Restricted Token backend deliberately does NOT call
 * this — its ACE is the standing cross-run reuse cache, and revoking it would
 * force the next invocation to re-propagate the whole workspace tree.
 *
 * Rebuilds the DACL without any ACE matching the given SID, then applies it
 * back to the directory. Note that the apply re-propagates through the tree.
 *
 * @param workspace  Workspace directory path
 * @param sid        Capability SID whose ACE should be removed
 * @return true on success, false on failure
 */
bool removeWorkspaceWriteAcl(PCWSTR workspace, PSID sid) {
    // Same per-path lock as the grant path: revoking is the mirror of granting
    // and must not interleave with a peer's read-merge-write.
    AclPathLock pathLock;
    if (!pathLock.acquire(workspace)) return false;

    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD err = GetNamedSecurityInfoW(
        (LPWSTR)workspace, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL, &dacl, NULL, &sd);
    if (err != ERROR_SUCCESS || !dacl) { LocalFree(sd); return false; }

    // Size the new DACL from the real ACE sizes. A per-ACE estimate is always
    // too small (real ACEs carry their SID; sizeof(ACCESS_ALLOWED_ACE) does
    // not) and would produce a truncated DACL whose AddAce calls fail.
    DWORD keepCount = 0, keepSize = sizeof(ACL);
    for (DWORD i = 0; i < dacl->AceCount; i++) {
        ACE_HEADER* ace = NULL;
        if (!GetAce(dacl, i, (void**)&ace)) continue;
        PSID aceSid = NULL;
        if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE)
            aceSid = (PSID)&((ACCESS_ALLOWED_ACE*)ace)->SidStart;
        else if (ace->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE)
            aceSid = (PSID)&((ACCESS_ALLOWED_CALLBACK_ACE*)ace)->SidStart;
        else { keepCount++; keepSize += ace->AceSize; continue; }
        if (!EqualSid(aceSid, sid)) { keepCount++; keepSize += ace->AceSize; }
    }

    // Rebuild DACL without the target SID's ACEs
    PACL newDacl = (PACL)LocalAlloc(LPTR, keepSize);
    if (!newDacl) { LocalFree(sd); return false; }
    if (!InitializeAcl(newDacl, keepSize, ACL_REVISION)) {
        LocalFree(newDacl);
        LocalFree(sd);
        return false;
    }

    BOOL aclComplete = TRUE;
    for (DWORD i = 0; i < dacl->AceCount; i++) {
        ACE_HEADER* ace = NULL;
        if (!GetAce(dacl, i, (void**)&ace)) continue;
        PSID aceSid = NULL;
        if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE)
            aceSid = (PSID)&((ACCESS_ALLOWED_ACE*)ace)->SidStart;
        else if (ace->AceType == ACCESS_ALLOWED_CALLBACK_ACE_TYPE)
            aceSid = (PSID)&((ACCESS_ALLOWED_CALLBACK_ACE*)ace)->SidStart;
        if (aceSid && EqualSid(aceSid, sid)) continue;
        // Never write back a partially built DACL: a failed AddAce would
        // silently drop the remaining ACEs (e.g. the user's own access)
        // from the directory.
        if (!AddAce(newDacl, ACL_REVISION, MAXDWORD, ace, ace->AceSize)) {
            aclComplete = FALSE;
            break;
        }
    }

    if (aclComplete) {
        err = SetNamedSecurityInfoW(
            (LPWSTR)workspace, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            NULL, NULL, newDacl, NULL);
    } else {
        err = ERROR_INVALID_ACL;
    }
    LocalFree(newDacl);
    LocalFree(sd);
    return err == ERROR_SUCCESS;
}
