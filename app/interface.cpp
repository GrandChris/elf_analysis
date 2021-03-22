


#if defined(EMSCRIPTEN)
    #include <emscripten.h>
#else
    #define EMSCRIPTEN_KEEPALIVE
#endif

#ifdef EMSCRIPTEN
#ifndef NODERAWFS
    // mount the current folder as a NODEFS instance
    // inside of emscripten
    #include <emscripten.h>

    bool initFileSystem()
    {
        EM_ASM(
            FS.mkdir('/working');
            FS.mount(NODEFS, {root : './'}, '/working'););
        return true;
    }
    bool isFileSystemInitialized = initFileSystem();

#endif
#endif



#include "elf_analysis.h"


extern "C" {

EMSCRIPTEN_KEEPALIVE
void sayHi() {
  printf("Hi!\n");
}

EMSCRIPTEN_KEEPALIVE
int daysInWeek() {
  return 7;
}

EMSCRIPTEN_KEEPALIVE
unsigned int read_file(char const * filename);

EMSCRIPTEN_KEEPALIVE
unsigned int read_file_debug(char const * filename);

EMSCRIPTEN_KEEPALIVE
char const * get_filename();

EMSCRIPTEN_KEEPALIVE
unsigned int get_lines_size();

EMSCRIPTEN_KEEPALIVE
unsigned int get_address(unsigned int line);

EMSCRIPTEN_KEEPALIVE
char const * get_opcode_description(unsigned int line);

EMSCRIPTEN_KEEPALIVE
unsigned int get_branch_destination(unsigned int line);


EMSCRIPTEN_KEEPALIVE
char const * get_line_filename(unsigned int line);

EMSCRIPTEN_KEEPALIVE
char const * get_line_path(unsigned int line);

EMSCRIPTEN_KEEPALIVE
unsigned int get_line_line(unsigned int line);

EMSCRIPTEN_KEEPALIVE
unsigned int get_line_column(unsigned int line);

EMSCRIPTEN_KEEPALIVE
unsigned int get_line_isEndSequence(unsigned int line);


EMSCRIPTEN_KEEPALIVE
char const * get_branch_destination_line_filename(unsigned int line);

EMSCRIPTEN_KEEPALIVE
char const * get_branch_destination_line_path(unsigned int line);

EMSCRIPTEN_KEEPALIVE
unsigned int get_branch_destination_line_line(unsigned int line);

EMSCRIPTEN_KEEPALIVE
unsigned int get_branch_destination_line_column(unsigned int line);

EMSCRIPTEN_KEEPALIVE
unsigned int get_branch_destination_line_isEndSequence(unsigned int line);


// char const * get_filename(unsigned int table, unsigned int index);

// EMSCRIPTEN_KEEPALIVE
// char const * get_target_line(unsigned int table, unsigned int index);
// char const * get_target_line(unsigned int table, unsigned int index);

// EMSCRIPTEN_KEEPALIVE
// void delete_table(unsigned int table);

}



// ################# Implementation ###################

DisassembledFile disassembledFile = {};

extern "C" {

unsigned int read_file(char const * filename) {
    disassembledFile = disassembleFile(filename, false);
    return true;
}

unsigned int read_file_debug(char const * filename) {
    disassembledFile = disassembleFile(filename, true);
    return true;
}


char const * get_filename() {
    return disassembledFile.filename.c_str();
}

unsigned int get_lines_size() {
    return disassembledFile.lines.size();
}

unsigned int get_address(unsigned int line) {
    return disassembledFile.lines[line].address;
}

char const * get_opcode_description(unsigned int line) {
    return disassembledFile.lines[line].opcode_description.c_str();
}

unsigned int get_branch_destination(unsigned int line) {
    return disassembledFile.lines[line].branch_destination;
}


char const * get_line_filename(unsigned int line) {
    return disassembledFile.lines[line].line.filename.c_str();
}

char const * get_line_path(unsigned int line) {
    return disassembledFile.lines[line].line.path.c_str();
}

unsigned int get_line_line(unsigned int line) {
    return disassembledFile.lines[line].line.line;
}

unsigned int get_line_column(unsigned int line) {
    return disassembledFile.lines[line].line.column;
}

unsigned int get_line_isEndSequence(unsigned int line) {
    return disassembledFile.lines[line].line.isEndSequence;
}


char const * get_branch_destination_line_filename(unsigned int line) {
    return disassembledFile.lines[line].branch_destination_line.filename.c_str();
}

char const * get_branch_destination_line_path(unsigned int line) {
    return disassembledFile.lines[line].branch_destination_line.path.c_str();
}

unsigned int get_branch_destination_line_line(unsigned int line) {
    return disassembledFile.lines[line].branch_destination_line.line;
}

unsigned int get_branch_destination_line_column(unsigned int line) {
    return disassembledFile.lines[line].branch_destination_line.column;
}

unsigned int get_branch_destination_line_isEndSequence(unsigned int line) {
    return disassembledFile.lines[line].branch_destination_line.isEndSequence;
}


}




// #include "disassembler.h"
// #include <iostream>
// #include <vector>


// struct branch {
//     uint32_t source_address;
//     std::string source_line;
//     uint32_t target_address;
//     std::string target_line;
// };

// std::vector<branch> branches;


// extern "C" {

// // EMSCRIPTEN_KEEPALIVE
// // int create_address_table(char const * filename) {
// //     try
// //     {
// //         std::cout << "filename: " << filename << std::endl;

// //         branches.clear();

// //         // read elf file
// //         auto const loader = std::make_shared<elf_file_loader>(filename);
// //         elf::elf ef(loader);
// //         auto const elf_loader = dwarf::elf::create_loader(ef);
// //         dwarf::dwarf dw(elf_loader);

// //         // parse .text section
// //         auto const & text = ef.get_section(".text");
// //         uint8_t const * data2 = static_cast<uint8_t const *>(text.data());
// //         disassembler dis(CS_ARCH_ARM, CS_MODE_THUMB);

// //         auto const data2_span = std::span(data2, text.size());
// //         auto code = dis(data2_span, text.get_hdr().addr);

// //         for(auto & elem : code) {

// //             if(elem.id == ARM_INS_BL) {
// //                 uint32_t const sourceAddress = static_cast<uint32_t>(elem.address);
// //                 uint32_t targetAddress = 0;
// //                 if(elem.detail->arm.op_count == 1) {
// //                     targetAddress = elem.detail->arm.operands[0].imm;
// //                 }

// //                 branches.push_back({.source_address = sourceAddress, .target_address = targetAddress});
// //             }
// //         }

// //         // map addresses to lines
// //         for(auto & elem: branches) {
// //             elem.source_line = find_address(dw, elem.source_address);
// //             elem.target_line = find_address(dw, elem.target_address);
// //         }
// //     }
// //     catch (std::exception const &e)
// //     {
// //         std::cout << e.what() <<  std::endl;
// //         return 1;
// //     }

// //      std::cout << "finished" <<  std::endl;
// //     return 0;
// // }

// EMSCRIPTEN_KEEPALIVE
// unsigned int table_size() {
//     return branches.size();
// }

// EMSCRIPTEN_KEEPALIVE
// char const * get_source_line(unsigned int index){
//     return branches[index].source_line.c_str();
// }

// EMSCRIPTEN_KEEPALIVE
// char const * get_target_line(unsigned int index){
//     return branches[index].target_line.c_str();
// }

// }