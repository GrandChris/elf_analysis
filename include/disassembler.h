


#include "capstone/capstone.h"
#include <stdexcept>
#include <span>
#include <cstddef>

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

class disassembled_code {
public:
    disassembled_code(cs_insn * insn, size_t count)
    : mInsn(insn), mCount(count)
    {

    }

    ~disassembled_code() {
        cs_free(mInsn, mCount);
        mCount = 0;
    }

    cs_insn const & operator[](size_t index) const {
        return mInsn[index];
    }

    size_t size() const {
        return mCount;
    }

    auto begin() const {
        return mInsn;
    }

    auto end() const {
        return mInsn + mCount;
    }

private:
    cs_insn * mInsn = nullptr;
    size_t mCount = 0;
};


class disassembler {
public:
    disassembler(cs_arch arch, cs_mode mode) {
        if (cs_open(arch, mode, &mHandle) != CS_ERR_OK) {
            throw std::runtime_error("failed to instantiate capstone");
        }

        cs_option(mHandle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON
    }

    
    ~disassembler() {
        cs_close(&mHandle);
    }

    
    disassembled_code operator()(std::span<const uint8_t> const code, uint32_t const address) {
        cs_insn * insn = nullptr;
        size_t const count = cs_disasm(mHandle, code.data(), code.size(), address, 0, &insn);

        return disassembled_code(insn, count);
    }

private:
    csh mHandle = 0;
};


