/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include "deFuncs.h"

int findFunctionAddressAndSyscallNumber(char* input, LPBYTE hModuleStart, DWORD hModuleSize) {
    // Check if the first two characters of input are "Nt"
    if (strncmp(input, "Nt", 2) == 0) {
        // Replace "Nt" with "Zw"
        input[0] = 'Z';
        input[1] = 'w';
    }

    // Allocate space for an array offunction information
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(hModuleStart + ((PIMAGE_DOS_HEADER)hModuleStart)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(hModuleStart + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* addressOfFunctions = (DWORD*)(hModuleStart + exports->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)(hModuleStart + exports->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)(hModuleStart + exports->AddressOfNameOrdinals);

    FunctionInfo* functionInfoArray = (FunctionInfo*)malloc(exports->NumberOfFunctions * sizeof(FunctionInfo));
    if (functionInfoArray == NULL) {
        printf("\n[-] Failed to allocate memory\n");
        return -1;
    }

    DWORD i;
    for (i = 0; i < exports->NumberOfNames; i++) {

        // Get the name of the function
        char* functionName = (char*)(hModuleStart + addressOfNames[i]);

        // Get the address of the function
        DWORD functionAddress = (DWORD)(ULONG_PTR)(hModuleStart + addressOfFunctions[addressOfNameOrdinals[i]]);

        // Store the function name and address in the array
        functionInfoArray[i].functionName = functionName;
        functionInfoArray[i].functionAddress = functionAddress;
   }

    // Sort the array based on the function addresses
    qsort(functionInfoArray, exports->NumberOfFunctions, sizeof(FunctionInfo), compareFunctionInfo);

    // Declare a variable to keep track of the syscall number
    int syscallNumber = 0;

    // Declare a flag variable to stop the loop when the desired input is found
    int inputFound = 0;

    // Find the function address and syscall number
    for (i = 0; i < exports->NumberOfFunctions; i++) {
        if (functionInfoArray[i].functionAddress != 0 && (_strnicmp(functionInfoArray[i].functionName, "Zw", 2) == 0)) {
            // Check if the input function is found
            if (strcmp(functionInfoArray[i].functionName, input) == 0) {
                inputFound = 1;
                break;
            }
            syscallNumber++;
        }
    }

    // Free the memory used by the function information array
    free(functionInfoArray);

    if (inputFound) {
        return syscallNumber;
    } else {
        return -1;
    }
}

SyscallInfo getSyscallInfo(char* input) {
    
    SyscallInfo info = { 0 };

    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (hNtDll == NULL) {
        printf("\n[-] Error loading ntdll.dll\n");
        return info;
    }

    LPBYTE hNtDllStart = (LPBYTE)hNtDll;
    info.hNtDllEnd = hNtDllStart + ((PIMAGE_NT_HEADERS)(hNtDllStart + ((PIMAGE_DOS_HEADER)hNtDllStart)->e_lfanew))->OptionalHeader.SizeOfImage;
            
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)hNtDll + ((PIMAGE_DOS_HEADER)hNtDll)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hNtDll + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* addressOfFunctions = (DWORD*)((LPBYTE)hNtDll + exports->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)((LPBYTE)hNtDll + exports->AddressOfNames);
    WORD* addressOfNameOrdinals = (WORD*)((LPBYTE)hNtDll + exports->AddressOfNameOrdinals);
    DWORD i;
   
    for (i = 0; i < exports->NumberOfNames; i++) {
        
        DWORD nameRVA = addressOfNames[i];
        char* functionName = (char*)((LPBYTE)hNtDll + nameRVA);
        
        if (strcmp(functionName, input) == 0) {
            DWORD functionRVA = addressOfFunctions[addressOfNameOrdinals[i]];
            info.syscallNum = *((unsigned int*)(hNtDllStart + functionRVA + 4));
            unsigned int bytesSequence = *((unsigned int*)(hNtDllStart + functionRVA));

            info.functionAddress = hNtDllStart + functionRVA;
            printf("\n      [>] Function %s found at 0x%p", input, info.functionAddress); // (LPVOID)GetXAddress(hNtDll, input)
            
            // Declare a flag variable to indicate if the sequence is found
            int sequenceFound = 0;

            // We're checking if the syscall is hooked
            if ((bytesSequence & 0xff) == 0xe9) { // this means: if the FIRST byte of bytesSequence is 0xe9
                printf("\n      [!] The bytes sequence starts with 0xe9 == (PROB. HOOKED)");
                printf("\n      [=] Bytes: 0x%x\n", bytesSequence);

                info.syscallNum = findFunctionAddressAndSyscallNumber(input, hNtDllStart, (DWORD)(ULONG_PTR)info.hNtDllEnd);

                // Check if the first two characters of input are "Zw"
                if (strncmp(input, "Zw", 2) == 0) {
                    // Replace "Nt" with "Zw"
                    input[0] = 'N';
                    input[1] = 't';
                }

                if (info.syscallNum != -1) {
                    printf("\n      [+] Syscall number: 0x%02x\n", info.syscallNum);
                    sequenceFound = 1;
                    break;
                }

                return info;
            }

            if (info.syscallNum < 0xfff) {
                printf("\n      [+] Syscall number: 0x%02x\n", info.syscallNum);
            } else {
                printf("\n");
            }

            return info;
        }
    }

    return info;
}

LPBYTE find0f05c3Sequence(LPBYTE functionAddress, LPBYTE ntdllEnd) {
    LPBYTE p = functionAddress;
    BOOL found = FALSE;
    while (p < ntdllEnd) {
        if (*p == 0x0f && *(p + 1) == 0x05 && *(p + 2) == 0xC3) {
            found = TRUE;
            DWORD offset = (DWORD)(p - functionAddress);
            printf("      [+] Found syscall instruction at 0x%p\n      [+] %d bytes from function address\n\n", p, offset);
            break;
        }
        p++;
    }
    if (!found) {
        printf("      [-] Could not find syscall instruction, return sysInstruc()\n\n");
        return (LPBYTE)sysInstruc;
        BOOL found = TRUE;
    }
    return found ? p : NULL;
}