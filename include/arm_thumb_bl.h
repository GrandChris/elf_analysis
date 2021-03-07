// 
// File: arm_thumb_bl.h
// Author: GrandChris
// Date: 2021-03-07
// Brief: Decoding of a bl instructions from arm thumb code
//

#pragma once

#include <cstdint>
#include <cstddef>
#include <cassert>


///
/// \class   arm_thumb_bl
/// \brief   Branch with Link (immediate) calls a subroutine at a PC-relative address.
/// \details https://web.eecs.umich.edu/~prabal/teaching/eecs373-f10/readings/ARMv7-M_ARM.pdf A6.7.18 BL
///
class arm_thumb_bl {
public:
    ///////////////////////////////////////////////////////////////////////////////
    // Constructor

    // explicit arm_thumb_bl(uint32_t instruction, uint32_t pc);
    explicit arm_thumb_bl(uint16_t instr1, uint16_t instr2, uint32_t pc);

    ///////////////////////////////////////////////////////////////////////////////
    // Member functions

    uint32_t getTargetAddress() const;

    ///////////////////////////////////////////////////////////////////////////////
    // Static functions

    static uint16_t const opcode      = 0b1111'0000'0000'0000;
    
    static uint16_t const opcode_mask = 0b1111'1000'0000'0000;
    static uint16_t const s_mask      = 0b0000'0100'0000'0000;
    static uint16_t const imm10_mask =  0b0000'0011'1111'1111;

    static uint16_t const const_mask =  0b1101'0000'0000'0000;
    static uint16_t const imm11_mask =  0b0000'0111'1111'1111;
    static uint16_t const j2_mask    =  0b0000'1000'0000'0000;
    static uint16_t const j1_mask    =  0b0010'0000'0000'0000;

    static bool isValid(uint16_t instr1) {
        return (instr1 & opcode_mask) == opcode;
    }

    static bool isValid(uint16_t instr1, uint16_t instr2) {
        bool const isFirstValid = isValid(instr1);
        bool const isSecondValid = (instr2 & const_mask) == const_mask;

        return isFirstValid && isSecondValid;
    }



private:

    ///////////////////////////////////////////////////////////////////////////////
    // Private member functions

    static constexpr int32_t getImm32(uint16_t instr1, uint16_t instr2);

    uint16_t const mInstr1;
    uint16_t const mInstr2;
    uint32_t const mPc;

    ///////////////////////////////////////////////////////////////////////////////
    // Static functions

    static constexpr size_t get_offset(uint32_t mask) {
        if(mask == 0) {
            return 0;
        }
        
        size_t res = 0;
        while(!(mask & 0b1)) {
            mask = mask >> 1;
            ++res;
        }

        return res;
    }

    static constexpr uint32_t get_bits(uint32_t const val, uint32_t const mask) {
        return (val & mask) >> get_offset(mask);
    }

    static constexpr uint16_t swap_bytes(uint16_t const val) {
        uint16_t const top = val << 8;
        uint16_t const bot = val >> 8;

        return top | bot;
    }

};


///////////////////////////////////////////////////////////////////////////////
// Implementation

#include <stdexcept>

///
/// \brief  Constructor
/// \param instruction   arm thumb instruction
///
inline arm_thumb_bl::arm_thumb_bl(uint16_t instr1, uint16_t instr2, uint32_t pc)
    : mInstr1(instr1), mInstr2(instr2), mPc(pc)
{
    assert((mInstr1 & opcode_mask) == opcode);
    assert((mInstr2 & const_mask) == const_mask);
}

///
/// \brief  Calculates imm32
///
inline constexpr int32_t arm_thumb_bl::getImm32(uint16_t instr1, uint16_t instr2)
{
    uint32_t const s = get_bits(instr1, s_mask);
    uint32_t const j1 = get_bits(instr2, j1_mask);
    uint32_t const j2 = get_bits(instr2, j2_mask);

    uint32_t const imm10 = get_bits(instr1, imm10_mask);
    uint32_t const imm11 = get_bits(instr2, imm11_mask);

    uint32_t const i1 = !(j1 ^ s);
    uint32_t const i2 = !(j2 ^ s);

    int32_t imm32 = 0;
    imm32 = (~imm32) * s;
    imm32 = imm32 << 24 | i1 << 23 | i2 << 22 | imm10 << 12 | imm11 << 1;

    return imm32;
}

///
/// \brief  Returns the branch address
///
uint32_t arm_thumb_bl::getTargetAddress() const {
    return (mPc + 4) + getImm32(mInstr1, mInstr2); 
}