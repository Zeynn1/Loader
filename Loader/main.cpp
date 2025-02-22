#include <windows.h>
#include <iostream>
#include "pe_loader.h"
#include "payload.h"
#include "crc32.h"
#include "antitamper.h"

int main()
{
    constexpr uint8_t XOR_KEY = 0x5A;

    LPVOID ep = 0;
    BYTE* baseAlloc = ManualMapPE(payload, payload_size, XOR_KEY, ep);
    if (!ep) {
        std::cerr << "Echec du manual mapping" << std::endl;
        return -1;
    }

    // On crée un thread vers l'entry point
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ep, NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "[!] Echec CreateThread: " << GetLastError() << std::endl;
        return -2;
    }

    Sleep(100);

    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(baseAlloc);
    IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(baseAlloc + dosHeader->e_lfanew);
    SIZE_T sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

    uint32_t initialChecksum = crc32(baseAlloc, sizeOfImage);

    std::thread(AntiTamperThread, baseAlloc, sizeOfImage, initialChecksum).detach();

    // On attend la fin du thread
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    std::cout << "Terminé." << std::endl;
    return 0;
}