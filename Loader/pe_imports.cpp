#include "pe_imports.h"

bool ResolveImports(BYTE* baseAddress)
{
    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(baseAddress);
    IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(baseAddress + dosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY& importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.VirtualAddress) {
        return true;
    }

    IMAGE_IMPORT_DESCRIPTOR* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(baseAddress + importDir.VirtualAddress);

    while (importDesc->Name)
    {
        LPCSTR dllName = reinterpret_cast<LPCSTR>(baseAddress + importDesc->Name);

        //std::cout << "Resolve import de : " << dllName << std::endl;
        HMODULE hMod = LoadLibraryA(dllName);
        if (!hMod) {
            std::cerr << "[!] Echec LoadLibraryA : " << dllName << std::endl;
            return false;
        }

        IMAGE_THUNK_DATA* thunkRef = reinterpret_cast<IMAGE_THUNK_DATA*>(baseAddress + importDesc->OriginalFirstThunk);
        IMAGE_THUNK_DATA* funcRef = reinterpret_cast<IMAGE_THUNK_DATA*>(baseAddress + importDesc->FirstThunk);

        if (!importDesc->OriginalFirstThunk) {
            thunkRef = reinterpret_cast<IMAGE_THUNK_DATA*>(baseAddress + importDesc->FirstThunk);
        }

        while (thunkRef->u1.AddressOfData)
        {
            FARPROC* funcAddr = reinterpret_cast<FARPROC*>(&funcRef->u1.Function);

            IMAGE_IMPORT_BY_NAME* importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(baseAddress + thunkRef->u1.AddressOfData);
            *funcAddr = GetProcAddress(hMod, importByName->Name);

            if (!*funcAddr) {
                std::cerr << "[!] Impossible de résoudre l'import : " << dllName << std::endl;
                return false;
            }

            thunkRef++;
            funcRef++;
        }

        importDesc++;
    }
    return true;
}