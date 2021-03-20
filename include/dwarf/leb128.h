// 
// File: uleb128.h
// Author: GrandChris
// Date: 2021-03-18
// Brief: Decodes a uleb128 number
//

#pragma once

#include <cstdint>
#include <cstddef>
#include <span>


inline size_t decodeUleb128(std::span<uint8_t const> const data, uint64_t & result) 
{
    size_t n = 0;
    size_t shift = 0;

    if(data.empty()) {
        result = 0;
        return 0;
    }

    while(true) {
        uint8_t const byte = data[n++];
        result |= (byte & 0x7F) << shift;
        shift += 7;

        if((byte & 0x80) == 0) 
        {   // success
            return n;
        }
        else if(n >= data.size()) 
        {   // decoding failed
            result = 0;
            return 0;
        }
    }    
}


inline size_t decodeSleb128(std::span<uint8_t const> const data, uint64_t & result) 
{
    size_t n = 0;
    size_t shift = 0;

    if(data.empty()) {
        result = 0;
        return 0;
    }

    while(true) {
        uint8_t const byte = data[n++];
        result |= (byte & 0x7F) << shift;
        shift += 7;

        if((byte & 0x80) == 0) 
        {   // success
            if(shift < 32 && (byte & 0x40) != 0) {
                result |= (~0 << shift);
            }

            return n;
        }
        else if(n >= data.size()) 
        {   // decoding failed
            result = 0;
            return 0;
        }
    }    
}
