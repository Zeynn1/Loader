#pragma once

#include "xor.h"

void xorDecryptPayload(uint8_t* data, size_t size, uint8_t XOR_KEY)
{
    for (size_t i = 0; i < size; i++) {
        data[i] ^= XOR_KEY;
    }
}