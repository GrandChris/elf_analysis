/// 
/// \file    disassembler.h
/// \author  GrandChris
/// \date    2021-03-18
/// \brief   C++ wrapper for the 'Capstone' library
///

#pragma once

#include "capstone/capstone.h"
#include <cstddef>
#include <span>
#include <stdexcept>

/// 
/// \class   disassembled_code
/// \brief   C++ wrapper of the result of the 'Capstone' library
/// \author  GrandChris
/// \date    2021-03-18
/// 
class disassembled_code {
public:

    /// 
    /// \brief   Constructor
    /// \author  GrandChris
    /// \date    2021-03-18
    /// \param insn Array of disassembled instructions  
    /// \param count Number of elements inside the Array
    ///
    disassembled_code(cs_insn * insn, size_t count)
    : mInsn(insn), mCount(count)
    {

    }

    /// 
    /// \brief   Destructor
    /// \author  GrandChris
    /// \date    2021-03-18
    ///
    ~disassembled_code() {
        cs_free(mInsn, mCount);
        mCount = 0;
    }

    /// 
    /// \brief   Access the instructions inside the array
    /// \author  GrandChris
    /// \date    2021-03-18
    /// \param index Index of the array  
    /// \return  A instuction
    ///
    cs_insn const & operator[](size_t index) const {
        return mInsn[index];
    }

    /// 
    /// \brief   Returns the size of the array
    /// \author  GrandChris
    /// \date    2021-03-18
    ///
    size_t size() const {
        return mCount;
    }

    /// 
    /// \brief   Returns an iterator to the beginning of the array
    /// \author  GrandChris
    /// \date    2021-03-18
    ///
    auto begin() const {
        return mInsn;
    }

    /// 
    /// \brief   Returns an iterator to the end of the array
    /// \author  GrandChris
    /// \date    2021-03-18
    ///
    auto end() const {
        return mInsn + mCount;
    }

private:
    cs_insn * mInsn = nullptr; // Array of instructions
    size_t mCount = 0;         // Size of the array
};


/// 
/// \class   disassembler
/// \brief   C++ wrapper for the 'Capstone' library; Disassembles the .text section of a file
/// \author  GrandChris
/// \date    2021-03-18
///
class disassembler {
public:
    /// 
    /// \brief   Constructor
    /// \author  GrandChris
    /// \date    2021-03-18
    /// \param arch Architecture type 
    /// \param mode Architecture mode type
    ///
    disassembler(cs_arch arch, cs_mode mode) {
        if (cs_open(arch, mode, &mHandle) != CS_ERR_OK) {
            throw std::runtime_error("failed to instantiate capstone");
        }

        cs_option(mHandle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON
        cs_option(mHandle, CS_OPT_SKIPDATA, CS_OPT_ON); // skip instructions if it cannot be parsed
    }

    /// 
    /// \brief   Destructor
    /// \author  GrandChris
    /// \date    2021-03-18
    ///
    ~disassembler() {
        cs_close(&mHandle);
    }

    /// 
    /// \brief   Disassemble a '.text' section
    /// \author  GrandChris
    /// \date    2021-03-18
    /// \param code Byte array of the '.text' section of an .elf file 
    /// \param address Virtual address of the '.text' section (listed in the .elf file)
    /// \return An array of disassembled instuctions
    ///
    disassembled_code operator()(std::span<const uint8_t> const code, uint32_t const address) {
        cs_insn * insn = nullptr;
        size_t const count = cs_disasm(mHandle, code.data(), code.size(), address, 0, &insn);

        return disassembled_code(insn, count);
    }

private:
    csh mHandle = 0;    // Pointer to the allocated instance from 'capstone'
};


