// parses the line table

#pragma once

#include <string>
#include <iostream>
#include "uleb128.h"

struct line_table_entry {
    uint32_t address;
    std::string filename;
    uint32_t line_number;
    uint32_t column_number;
    bool is_beginning_of_source_statement;

    // A sequence of instructions where only the first
    // instruction may be a branch target and only the
    // last instruction may transfer control. A
    // subprogram invocation is defined to be an exit
    // from a basic block.
    bool is_beginning_of_basic_block; 
};

bool default_is_stmt = false;




bool isSpecialOpcode(uint8_t const opcode, LineNumberProgramHeader const & header) {
    return opcode <= header.opcode_base;
}

auto decodeSpecialOpcode(uint8_t opcode, LineNumberProgramHeader const & header) {
    uint32_t const adjusted_opcode = opcode - header.opcode_base;
    uint32_t const address_increment = (adjusted_opcode / header.line_range); // * header.minimum_instruction_length ;
    int32_t const line_increment = header.line_base + (adjusted_opcode % header.line_range);

    struct SpecialOpcode {
        uint32_t address_increment;
        int32_t line_increment;
    };

    return SpecialOpcode{address_increment, line_increment};
}


uint32_t encodeOpcode(uint32_t const line_increment, uint32_t const address_increment, LineNumberProgramHeader const & header) {
    uint32_t const opcode = (line_increment - header.line_base) +
        (header.line_range * address_increment) + header.opcode_base;

    return opcode;
}







class StateMachine
{
private:
    StateMachineRegisters mReg;

    std::vector<StateMachineRegisters> mLineTable;

    LineNumberProgramHeader mHeader;

public:

    StateMachine(LineNumberProgramHeader const & header) : mHeader(header) {
        reset();
    }

     void reset() {
         mReg.address = 0;
         mReg.op_index = 0;
         mReg.file = 1;
         mReg.line = 1;
         mReg.column = 0;
         mReg.is_stmt = mHeader.default_is_stmt;
         mReg.basic_block = false;
         mReg.end_sequence = false;
         mReg.prologue_end = false;
         mReg.epilogue_begin = false;
         mReg.isa = 0;
         mReg.discriminator = 0;
    }

    void setLineNumberProgramHeader(LineNumberProgramHeader const & header) {
        mHeader = header;
    }

    void setLineNumberProgramHeader(LineNumberProgramHeader && header) {
        mHeader = std::move(header);
    }

    void specialOpcode(int32_t add_line, uint32_t add_address) {
        mReg.line += add_line;
        mReg.address += add_address * mHeader.minimum_instruction_length;

        std::cout << std::hex << mReg.address << std::dec << " " << mHeader.file_names[mReg.file -1].name << 
        ":" << mReg.line << ":" << mReg.column << std::endl;

        mLineTable.push_back(mReg);

        mReg.basic_block = false;
        mReg.prologue_end = false;
        mReg.epilogue_begin = false;
    }







    // 1.
    // The DW_LNS_copy opcode takes no operands. It appends a row to the matrix using the 
    // current values of the state-machine registers. Then it sets the basic_block, prologue_end 
    // and epilogue_begin registers to “false.” 
    void dw_lns_copy() {
        std::cout << std::hex << mReg.address << std::dec << " " << mHeader.file_names[mReg.file -1].name << 
        ":" << mReg.line << ":" << mReg.column << std::endl;

        mLineTable.push_back(mReg);

        mReg.basic_block = false;
        mReg.prologue_end = false;
        mReg.epilogue_begin = false;
    }

    // 2.
    // The DW_LNS_advance_pc opcode takes a single unsigned LEB128 operand, multiplies it by 
    // the minimum_instruction_length field of the header, and adds the result to the address
    // register of the state machine. 
    void dw_lns_advance_pc(uint32_t leb128_operand) {
        mReg.address += leb128_operand; // * mHeader.minimum_instruction_length;
    }

    // 3.
    // The DW_LNS_advance_line opcode takes a single signed LEB128 operand and adds that 
    // value to the line register of the state machine. 
    void dw_lns_advance_line(uint32_t leb128_operand) {
        mReg.line += leb128_operand;
    }

    // 4.
    // The DW_LNS_set_file opcode takes a single unsigned LEB128 operand and stores it in the 
    // file register of the state machine
    void dw_lns_set_file(uint32_t leb128_operand)  {
        mReg.file = leb128_operand;
    }

    // 5
    // The DW_LNS_set_column opcode takes a single unsigned LEB128 operand and stores it in 
    // the column register of the state machine. 
    void dw_lns_set_column(uint32_t leb128_operand) {
        mReg.column = leb128_operand;
    }

    // 6
    // The DW_LNS_negate_stmt opcode takes no operands. It sets the is_stmt register of the 
    // state machine to the logical negation of its current value. 
    void dw_lns_negate_stmt() {
        mReg.is_stmt = !mReg.is_stmt;
    }

    // 7
    // The DW_LNS_set_basic_block opcode takes no operands. It sets the basic_block register 
    // of the state machine to “true.”
    void dw_lns_set_basic_block() {
        mReg.basic_block = true;
    }

    // 8
    // The DW_LNS_const_add_pc opcode takes no operands. It multiplies the address increment 
    // value corresponding to special opcode 255 by the minimum_instruction_length field of 
    // the header, and adds the result to the address register of the state machine. 
    // When the line number program needs to advance the address by a small amount, it can use a 
    // single special opcode, which occupies a single byte. When it needs to advance the address by 
    // up to twice the range of the last special opcode, it can use DW_LNS_const_add_pc followed 
    // by a special opcode, for a total of two bytes. Only if it needs to advance the address by more 
    // than twice that range will it need to use both DW_LNS_advance_pc and a special opcode, 
    // requiring three or more bytes. 
    void dw_lns_const_add_pc() {
        auto specialOpcode255 = decodeSpecialOpcode(255, mHeader);

        mReg.address += specialOpcode255.address_increment * mHeader.minimum_instruction_length;
    }

    // 9 
    // The DW_LNS_fixed_advance_pc opcode takes a single uhalf (unencoded) operand and adds 
    // it to the address register of the state machine. This is the only standard opcode whose 
    // operand is not a variable length number. It also does not multiply the operand by the 
    // minimum_instruction_length field of the header. DWARF Debugging Information Format, Version 3 
    // Existing assemblers cannot emit DW_LNS_advance_pc or special opcodes because they 
    // cannot encode LEB128 numbers or judge when the computation of a special opcode 
    // overflows and requires the use of DW_LNS_advance_pc. Such assemblers, however, can use 
    // DW_LNS_fixed_advance_pc instead, sacrificing compression. 
    void dw_lns_fixed_advance_pc(uint16_t operand) {
        mReg.address += operand;
    }

    // 10
    // The DW_LNS_set_prologue_end opcode takes no operands. It sets the prologue_end
    // register to “true”. 
    // When a breakpoint is set on entry to a function, it is generally desirable for execution to be 
    // suspended, not on the very first instruction of the function, but rather at a point after the 
    // function's frame has been set up, after any language defined local declaration processing has 
    // been completed, and before execution of the first statement of the function begins. Debuggers 
    // generally cannot properly determine where this point is. This command allows a compiler to 
    // communicate the location(s) to use. 
    // In the case of optimized code, there may be more than one such location; for example, the 
    // code might test for a special case and make a fast exit prior to setting up the frame. 
    // Note that the function to which the prologue end applies cannot be directly determined from 
    // the line number information alone; it must be determined in combination with the subroutine 
    // information entries of the compilation (including inlined subroutines). 
    void dw_lns_set_prologue_end() {
        mReg.prologue_end = true;
    }

    // 11
    // The DW_LNS_set_epilogue_begin opcode takes no operands. It sets the epilogue_begin
    // register to “true”. 
    // When a breakpoint is set on the exit of a function or execution steps over the last executable 
    // statement of a function, it is generally desirable to suspend execution after completion of the 
    // last statement but prior to tearing down the frame (so that local variables can still be 
    // examined). Debuggers generally cannot properly determine where this point is. This 
    // command allows a compiler to communicate the location(s) to use. 
    // Note that the function to which the epilogue end applies cannot be directly determined from 
    // the line number information alone; it must be determined in combination with the subroutine 
    // information entries of the compilation (including inlined subroutines). 
    // In the case of a trivial function, both prologue end and epilogue begin may occur at the same 
    // address. 
    void dw_lns_set_epilogue_begin() {
        mReg.epilogue_begin = true;
    }

    // 12
    // The DW_LNS_set_isa opcode takes a single unsigned LEB128 operand and stores that value 
    // in the isa register of the state machine. 
    void dw_lns_set_isa(uint32_t leb128_operand) {
        mReg.isa = leb128_operand;
    }

    // Extended 1
    // The DW_LINE_end_sequence opcode takes no operands. It sets the end_sequence register 
    // of the state machine to “true” and appends a row to the matrix using the current values of the 
    // state-machine registers. Then it resets the registers to the initial values specified above (see 
    // Section 6.2.2). Every line number program sequence must end with a 
    // DW_LNE_end_sequence instruction which creates a row whose address is that of the byte 
    // after the last target machine instruction of the sequence. 
    void dw_line_end_sequence() {
        mReg.end_sequence = true;

        std::cout << std::hex << mReg.address << std::dec << " " << mHeader.file_names[mReg.file -1].name << 
        ":" << mReg.line << ":" << mReg.column << std::endl;

        mLineTable.push_back(mReg);
        reset();
    }

    // Extended 2
    // The DW_LNE_set_address opcode takes a single relocatable address as an operand. The size 
    // of the operand is the size appropriate to hold an address on the target machine. It sets the 
    // address register to the value given by the relocatable address. 
    // All of the other line number program opcodes that affect the address register add a delta to 
    // it. This instruction stores a relocatable value into it instead. 
    void dw_line_set_address(uint32_t address) {
        mReg.address = address;
    }

    // Extended 3
    // The DW_LNE_define_file opcode takes four operands: 
    // 1. A null-terminated string containing a source file name. 
    // 2. An unsigned LEB128 number representing the directory index of the directory in which 
    // the file was found. 
    // 3. An unsigned LEB128 number representing the time of last modification of the file. 
    // 4. An unsigned LEB128 number representing the length in bytes of the file. 
    // The time and length fields may contain LEB128(0) if the information is not available. DWARF Debugging Information Format, Version 3 
    // Page 104 December 20, 2005 
    // The directory index represents an entry in the include_directories section of the line 
    // number program header. The index is LEB128(0) if the file was found in the current 
    // directory of the compilation, LEB128(1) if it was found in the first directory in the 
    // include_directories section, and so on. The directory index is ignored for file names that 
    // represent full path names. 
    // The files are numbered, starting at 1, in the order in which they appear; the names in the 
    // header come before names defined by the DW_LNE_define_file instruction. These numbers 
    // are used in the file register of the state machine. 
    void dw_line_define_file(char const * source_file_name, uint32_t leb128_directory_index,
        uint32_t leb128_last_time_modified, uint32_t leb128_file_length) {

        }

    // Extended 4
    // The DW_LNE_set_discriminator opcode takes a single parameter, an unsigned LEB128 
    // integer. It sets the discriminator register to the new value.
    void dw_lne_set_discriminator(uint32_t leb128_operand) {
        mReg.discriminator = leb128_operand;
    }
};




#include <iostream>

inline LineNumberProgramHeader ReadLineNumberProgramHeader(uint8_t const * & data) 
{
    using namespace std;

    LineNumberProgramHeader res = {};

    memcpy(&res.uint_length, data, sizeof(res.uint_length)); data += sizeof(res.uint_length);
    memcpy(&res.version, data, sizeof(res.version)); data += sizeof(res.version);
    memcpy(&res.header_length, data, sizeof(res.header_length)); data += sizeof(res.header_length);
    memcpy(&res.minimum_instruction_length, data, sizeof(res.minimum_instruction_length)); data += sizeof(res.minimum_instruction_length);
    // res.minimum_instruction_length = 1; // 
    
    memcpy(&res.default_is_stmt, data, sizeof(res.default_is_stmt)); data += sizeof(res.default_is_stmt);
    memcpy(&res.line_base, data, sizeof(res.line_base)); data += sizeof(res.line_base);
    memcpy(&res.line_range, data, sizeof(res.line_range)); data += sizeof(res.line_range);
    memcpy(&res.opcode_base, data, sizeof(res.opcode_base)); data += sizeof(res.opcode_base);
    assert(res.opcode_base == 13);

    for(size_t i = 0; i < std::size(res.standard_opcode_lengths); ++i) {
        memcpy(&res.standard_opcode_lengths[i], data, sizeof(res.standard_opcode_lengths[i])); data += sizeof(res.standard_opcode_lengths[i]);
    }

    while(*data != 0) {
        res.include_directories.push_back(std::string(reinterpret_cast<char const *>(data)));
        data += res.include_directories.back().size()+1;
    }
    data += 1;

    while(*data != 0) {
        LineNumberProgramHeader::file_name r = {};
        r.name = std::string(reinterpret_cast<char const *>(data));
        data += r.name.size()+1;

        unsigned n = 0;
        r.include_directories_index = decodeULEB128(data, &n);
        data += n;

        unsigned n2 = 0;
        r.time_last_modified = decodeULEB128(data, &n2);
        data += n2;

        unsigned n3 = 0;
        r.size = decodeULEB128(data, &n3);
        data += n3;

        res.file_names.push_back(r);        
    }    
    data += 1;

    cout << "uint_length: " << res.uint_length << endl;
    cout << "version: " << res.version << endl;
    cout << "header_length: " << res.header_length << endl;
    cout << "default_is_stmt: " << static_cast<uint32_t>(res.default_is_stmt) << endl;
    cout << "line_base: " << static_cast<int32_t>(res.line_base) << endl;
    cout << "line_range: " << static_cast<uint32_t>(res.line_range) << endl;
    cout << "opcode_base: " << static_cast<uint32_t>(res.opcode_base) << endl;

    for(size_t i = 0; i < std::size(res.standard_opcode_lengths); ++i) {
        cout << "standard_opcode_lengths[" << i << "]: " << static_cast<uint32_t>(res.standard_opcode_lengths[i]) << endl;
    }
    cout << "number directories: " << res.include_directories.size() << endl;

    cout << "number file_names: " << res.file_names.size() << endl;

    return res;
}


void create_line_table(uint8_t const data[]) {

    uint8_t const * data_header = data;

    auto const header = ReadLineNumberProgramHeader(data_header);
    size_t const header_size = data_header - data;
    size_t const data_size = header.uint_length + sizeof(header.uint_length) - header_size;
    
    StateMachine stateMachine(header);



    for(size_t i = 0; i < data_size; ++i) {

        auto leb128_operand = [&]() {
            unsigned n = 0;
            uint32_t const op1 = decodeULEB128(&data[header_size + i+1], &n);
            i += n;
            assert(n <= 4);
            return op1;
        };

        auto uint16_operand = [&]() {
            size_t n = 2;
            uint16_t const * op1 = reinterpret_cast<uint16_t const *>(&data[header_size + i+1]);
            i += n;
            return *op1;
        };

        auto uint32_operand = [&]() {
            size_t n = 4;
            uint32_t const * op1 = reinterpret_cast<uint32_t const *>(&data[header_size + i+1]);
            i += n;
            return *op1;
        };

        auto uint64_operand = [&]() {
            size_t n = 8;
            uint64_t const * op1 = reinterpret_cast<uint64_t const *>(&data[header_size + i+1]);
            i += n;
            return *op1;
        };

        auto const opcode = data[header_size + i];

        std::vector<uint8_t> opcodes(&data[header_size + i], &data[header_size + i+25]);


        switch(opcode) {
            case 0: // extended opcode
                {
                    
                    uint32_t extendedOpcodeSize = leb128_operand();
                    i += 1;
                    auto const extendedOpcode = data[header_size + i];
                    
                    switch(extendedOpcode) {
                        case 1:
                            stateMachine.dw_line_end_sequence();
                            break;
                        case 2:
                            if(extendedOpcodeSize == 5) {
                                stateMachine.dw_line_set_address(uint32_operand());
                            }
                            else if(extendedOpcodeSize == 9) {
                                stateMachine.dw_line_set_address(uint64_operand());
                            }
                            else {
                                assert(false);
                            }                            
                            break;
                        case 3:
                            assert(false);
                            // stateMachine.dw_line_define_file();
                            break;
                        case 4:
                            stateMachine.dw_lne_set_discriminator(leb128_operand());
                            break;
                        default:
                            assert(false);
                            break;
                        }
                }
                break;
            case 1:
                stateMachine.dw_lns_copy();
                break;
            case 2:
                stateMachine.dw_lns_advance_pc(leb128_operand());
                break;
            case 3:
                stateMachine.dw_lns_advance_line(leb128_operand());
                break;
            case 4:
                stateMachine.dw_lns_set_file(leb128_operand());
                break;
            case 5:
                stateMachine.dw_lns_set_column(leb128_operand());
                break;
            case 6:
                stateMachine.dw_lns_negate_stmt();
                break;
            case 7:
                stateMachine.dw_lns_set_basic_block();
                break;
            case 8:
                stateMachine.dw_lns_const_add_pc();
                break;
            case 9:
                stateMachine.dw_lns_fixed_advance_pc(uint16_operand());
                break;
            case 10:
                stateMachine.dw_lns_set_prologue_end();
                break;
            case 11:
                stateMachine.dw_lns_set_epilogue_begin();
                break;
            case 12:
                stateMachine.dw_lns_set_isa(leb128_operand());
                break;
            default:    // special opcode
                auto const decoded_opcode = decodeSpecialOpcode(opcode, header);
                auto const encoded_opcode = encodeOpcode(decoded_opcode.line_increment, decoded_opcode.address_increment, header);
                assert(encoded_opcode == opcode);
                
                stateMachine.specialOpcode(decoded_opcode.line_increment, decoded_opcode.address_increment);
                break;
        }
    }

    

}