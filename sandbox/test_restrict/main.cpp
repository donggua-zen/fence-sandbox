// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 AI Sandbox Contributors
//
// @file main.cpp
// @brief Test program for Windows Restricted Token + Restricting SIDs combinations.
//
// This is a diagnostic tool that tests various CreateRestrictedToken flag and
// SID combinations to verify which configurations allow child process creation.
// It is Windows-only and not part of the sandbox executable.
//
// Build: cl test_restricted.cpp /Fe:test_restricted.exe /EHsc

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <stdio.h>

/**
 * @brief Convert a SID string (e.g. "S-1-1-0") to a PSID.
 *
 * @param str  SID string in S-R-I-S-S... format
 * @return Allocated PSID (caller must LocalFree), or NULL on failure
 */
static PSID getSid(PCWSTR str) {
    PSID sid = NULL;
    ConvertStringSidToSidW(str, &sid);
    return sid;
}

/**
 * @brief Extract the user SID from a process token.
 *
 * @param hToken  Handle to a process token (TOKEN_QUERY required)
 * @return Allocated PSID (caller must LocalFree), or NULL on failure
 */
static PSID getUserSid(HANDLE hToken) {
    DWORD bufSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &bufSize);
    PTOKEN_USER user = (PTOKEN_USER)LocalAlloc(LPTR, bufSize);
    if (!user || !GetTokenInformation(hToken, TokenUser, user, bufSize, &bufSize)) {
        LocalFree(user);
        return NULL;
    }
    DWORD len = GetLengthSid(user->User.Sid);
    PSID result = (PSID)LocalAlloc(LPTR, len);
    if (result) CopySid(len, result, user->User.Sid);
    LocalFree(user);
    return result;
}

/**
 * @brief Extract the logon SID from a process token.
 *
 * The logon SID identifies the logon session and is needed as a restricting
 * SID when using CreateRestrictedToken with WRITE_RESTRICTED.
 *
 * @param hToken  Handle to a process token (TOKEN_QUERY required)
 * @return Allocated PSID (caller must LocalFree), or NULL on failure
 */
static PSID getLogonSid(HANDLE hToken) {
    DWORD bufSize = 0;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &bufSize);
    PTOKEN_GROUPS groups = (PTOKEN_GROUPS)LocalAlloc(LPTR, bufSize);
    if (!groups || !GetTokenInformation(hToken, TokenGroups, groups, bufSize, &bufSize)) {
        LocalFree(groups); return NULL;
    }
    PSID result = NULL;
    for (DWORD i = 0; i < groups->GroupCount; i++) {
        if (groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) {
            DWORD len = GetLengthSid(groups->Groups[i].Sid);
            result = (PSID)LocalAlloc(LPTR, len);
            if (result) CopySid(len, result, groups->Groups[i].Sid);
            break;
        }
    }
    LocalFree(groups);
    return result;
}

/**
 * @brief Test a single Restricted Token + SID combination.
 *
 * Creates a restricted token with the given flags and restricting SIDs,
 * then attempts to launch cmd.exe /c echo OK with that token. Reports
 * whether the process was created successfully and its exit code.
 *
 * @param label          Human-readable description for test output
 * @param flags          Flags for CreateRestrictedToken (e.g. WRITE_RESTRICTED)
 * @param restrictSids   Array of restricting SIDs (may be NULL if count is 0)
 * @param count          Number of restricting SIDs
 * @param creationFlags  Process creation flags (e.g. CREATE_SUSPENDED)
 * @return Exit code of the child process, or the Windows error code on failure
 */
static DWORD test_combination(PCWSTR label, DWORD flags,
    SID_AND_ATTRIBUTES* restrictSids, DWORD count, DWORD creationFlags)
{
    wprintf(L"  %-50s ", label);

    HANDLE hToken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken);

    HANDLE hRestrictToken = NULL;
    BOOL ok = CreateRestrictedToken(hToken, flags, 0, NULL, 0, NULL,
                                     count, restrictSids, &hRestrictToken);
    if (!ok) {
        DWORD err = GetLastError();
        CloseHandle(hToken);
        wprintf(L"CreateRestrictedToken FAILED (err=%lu)\n", err);
        return err;
    }

    // Duplicate as primary token for CreateProcessAsUserW
    HANDLE hPrimary = NULL;
    DuplicateTokenEx(hRestrictToken, MAXIMUM_ALLOWED, NULL,
                     SecurityImpersonation, TokenPrimary, &hPrimary);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    WCHAR cmd[] = L"cmd.exe /c echo OK";

    ok = CreateProcessAsUserW(hPrimary, NULL, cmd, NULL, NULL, FALSE,
                              creationFlags, NULL, NULL, &si, &pi);
    if (!ok) {
        DWORD err = GetLastError();
        wprintf(L"CreateProcessAsUserW FAILED (err=%lu)\n", err);
        CloseHandle(hPrimary); CloseHandle(hRestrictToken); CloseHandle(hToken);
        return err;
    }

    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    CloseHandle(hPrimary); CloseHandle(hRestrictToken); CloseHandle(hToken);

    // Exit codes 0 and 1 are considered normal (echo OK returns 0, cmd errors return 1)
    if (exitCode == 0 || exitCode == 1) {
        wprintf(L"PASS (exit=%lu)\n", exitCode);
    } else {
        wprintf(L"FAIL (exit=%lu = 0x%08lx)\n", exitCode, exitCode);
    }
    return exitCode;
}

int wmain() {
    HANDLE hToken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);

    PSID everyone = getSid(L"S-1-1-0");
    PSID logon = getLogonSid(hToken);
    PSID userSid = getUserSid(hToken);
    PSID wsSid = getSid(L"S-1-5-21-12345-67890-12345-67890");
    CloseHandle(hToken);

    wprintf(L"=== Restricted Token Combination Tests ===\n");
    wprintf(L"User SID:  "); { LPWSTR s; ConvertSidToStringSidW(userSid, &s); wprintf(L"%s\n", s); LocalFree(s); }
    wprintf(L"Logon SID: "); { LPWSTR s; ConvertSidToStringSidW(logon, &s); wprintf(L"%s\n", s); LocalFree(s); }
    wprintf(L"\n");

    DWORD cf = CREATE_SUSPENDED | CREATE_NEW_CONSOLE;

    // A: baseline — no restricting SIDs, just disable max privilege
    test_combination(L"A: DISABLE_MAX_PRIVILEGE only",
        DISABLE_MAX_PRIVILEGE, NULL, 0, cf);

    // B: WRITE_RESTRICTED + user's primary SID
    SID_AND_ATTRIBUTES u = { userSid, 0 };
    test_combination(L"B: +WRITE_RESTRICTED + user SID",
        DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED, &u, 1, cf);

    // C: WRITE_RESTRICTED + Everyone SID
    SID_AND_ATTRIBUTES e = { everyone, 0 };
    test_combination(L"C: +WRITE_RESTRICTED + Everyone",
        DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED, &e, 1, cf);

    // D: no WRITE_RESTRICTED + {Everyone, Logon, WS} as restricting SIDs
    SID_AND_ATTRIBUTES arr3[] = { {everyone,0}, {logon,0}, {wsSid,0} };
    test_combination(L"D: no WR + {Everyone,Logon,WS}",
        DISABLE_MAX_PRIVILEGE, arr3, 3, cf);

    // E: WRITE_RESTRICTED + {Everyone, Logon, WS}
    test_combination(L"E: +WR + {Everyone,Logon,WS}",
        DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED, arr3, 3, cf);

    // F: same as D but without CREATE_SUSPENDED / CREATE_NEW_CONSOLE
    test_combination(L"F: no WR + {E,L,WS} + flags=0",
        DISABLE_MAX_PRIVILEGE, arr3, 3, 0);

    // G: WRITE_RESTRICTED + {Everyone, Logon, WS} without special flags
    test_combination(L"G: +WR + {E,L,WS} + flags=0",
        DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED, arr3, 3, 0);

    // H: WRITE_RESTRICTED + workspace SID only, no special flags
    SID_AND_ATTRIBUTES ws = { wsSid, 0 };
    test_combination(L"H: +WR + WS only + flags=0",
        DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED, &ws, 1, 0);

    wprintf(L"\n=== Tests Complete ===\n");
    LocalFree(everyone); LocalFree(logon); LocalFree(userSid); LocalFree(wsSid);
    return 0;
}
