#pragma once

#include <windows.h>
#include <iostream>
#include <cstdint>
#include <chrono>
#include <thread>
#include "crc32.h"

void AntiTamperThread(BYTE* baseAddress, SIZE_T sizeOfImage, uint32_t initialChecksum);