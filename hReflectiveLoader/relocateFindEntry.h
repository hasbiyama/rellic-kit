/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include "getSyscall.h"

void __stdcall relocateFindEntry(BYTE* imageBase) {
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(imageBase + ((IMAGE_DOS_HEADER*)imageBase)->e_lfanew);
    IMAGE_OPTIONAL_HEADER* optionalHeader = &ntHeaders->OptionalHeader;
    DllEntryPointFunc dllEntryPoint = (DllEntryPointFunc)(imageBase + optionalHeader->AddressOfEntryPoint);
    InjectionContext* context = (InjectionContext*)(imageBase + optionalHeader->SizeOfImage);

    BYTE* baseDelta = imageBase - optionalHeader->ImageBase;
    if (baseDelta && optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        IMAGE_BASE_RELOCATION* relocation = (IMAGE_BASE_RELOCATION*)(imageBase + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (relocation->VirtualAddress) {
            UINT relocationCount = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* relocationInfo = (WORD*)(relocation + 1);
            for (UINT i = 0; i < relocationCount; ++i, ++relocationInfo) {
                if (RELOCATION_CONDITION(*relocationInfo)) {
                    UINT_PTR* address = (UINT_PTR*)(imageBase + relocation->VirtualAddress + (*relocationInfo & 0xFFF));
                    *address += (UINT_PTR)baseDelta;
                }
            }
            relocation = (IMAGE_BASE_RELOCATION*)((BYTE*)relocation + relocation->SizeOfBlock);
        }
    }

    if (optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        IMAGE_IMPORT_DESCRIPTOR* importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(imageBase + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (importDescriptor->Name) {
            char* moduleName = (char*)(imageBase + importDescriptor->Name);
            HINSTANCE moduleHandle = context->loadLibraryFunction(moduleName);

            ULONG_PTR* thunkRef = (ULONG_PTR*)(imageBase + importDescriptor->OriginalFirstThunk);
            ULONG_PTR* funcRef = (ULONG_PTR*)(imageBase + importDescriptor->FirstThunk);
            if (!thunkRef) thunkRef = funcRef;

            for (; *thunkRef; ++thunkRef, ++funcRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
                    *funcRef = (ULONG_PTR)context->getProcAddressFunction(moduleHandle, (char*)(*thunkRef & 0xFFFF));
                } else {
                    IMAGE_IMPORT_BY_NAME* import = (IMAGE_IMPORT_BY_NAME*)(imageBase + *thunkRef);
                    *funcRef = (ULONG_PTR)context->getProcAddressFunction(moduleHandle, import->Name);
                }
            }
            ++importDescriptor;
        }
    }

    if (optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        IMAGE_TLS_DIRECTORY* tls = (IMAGE_TLS_DIRECTORY*)(imageBase + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)(tls->AddressOfCallBacks);
        for (; callbacks && *callbacks; ++callbacks) {
            (*callbacks)(imageBase, DLL_PROCESS_ATTACH, NULL);
        }
    }

    dllEntryPoint(imageBase, DLL_PROCESS_ATTACH, NULL);
    context->dllModuleHandle = (HINSTANCE)imageBase;
}