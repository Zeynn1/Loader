#pragma once

#include <windows.h>
#include <cstdint>
#include <iostream>
#include <cstring>

#include "xor.h"
#include "pe_imports.h"

BYTE* ManualMapPE(const uint8_t* rawData, size_t rawSize, uint8_t XOR_KEY, LPVOID& entryPoint);