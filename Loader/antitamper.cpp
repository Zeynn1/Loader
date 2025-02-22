#include "antitamper.h"

void AntiTamperThread(BYTE* baseAddress, SIZE_T sizeOfImage, uint32_t initialChecksum) {
    while (true) {
        uint32_t currentChecksum = crc32(baseAddress, sizeOfImage);
        if (currentChecksum != initialChecksum) {
            std::cerr << "Modification détecte\n";
            ExitProcess(0);
        }
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
}