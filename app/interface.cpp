


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
unsigned int elf_analysis_analyse_data(uint8_t * data, unsigned int size);


EMSCRIPTEN_KEEPALIVE
char const * elf_analysis_get_filename();

EMSCRIPTEN_KEEPALIVE
unsigned int elf_analysis_get_lines_size();

EMSCRIPTEN_KEEPALIVE
unsigned int elf_analysis_get_address(unsigned int line);

EMSCRIPTEN_KEEPALIVE
char const * elf_analysis_get_opcode_description(unsigned int line);

EMSCRIPTEN_KEEPALIVE
unsigned int elf_analysis_get_branch_destination(unsigned int line);


EMSCRIPTEN_KEEPALIVE
char const * elf_analysis_get_line_filename(unsigned int line);

EMSCRIPTEN_KEEPALIVE
char const * elf_analysis_get_line_path(unsigned int line);

EMSCRIPTEN_KEEPALIVE
unsigned int elf_analysis_get_line_line(unsigned int line);

EMSCRIPTEN_KEEPALIVE
unsigned int elf_analysis_get_line_column(unsigned int line);

EMSCRIPTEN_KEEPALIVE
unsigned int elf_analysis_get_line_isStartSequence(unsigned int line);


EMSCRIPTEN_KEEPALIVE
char const * elf_analysis_get_branch_destination_line_filename(unsigned int line);

EMSCRIPTEN_KEEPALIVE
char const * elf_analysis_get_branch_destination_line_path(unsigned int line);

EMSCRIPTEN_KEEPALIVE
unsigned int elf_analysis_get_branch_destination_line_line(unsigned int line);

EMSCRIPTEN_KEEPALIVE
unsigned int elf_analysis_get_branch_destination_line_column(unsigned int line);

EMSCRIPTEN_KEEPALIVE
unsigned int elf_analysis_get_branch_destination_line_isStartSequence(unsigned int line);

}



// ################# Implementation ###################

DisassembledFile disassembledFile = {};

#include <iostream>

extern "C" {

/// 
/// \brief   Analyses the data and stores the result in a static variable
/// \author  GrandChris
/// \date    2021-03-18
/// \param data Raw byte array of a .elf file 
/// \param size Size of the array
/// \return  true
///
unsigned int elf_analysis_analyse_data(uint8_t * data, unsigned int size) {
    disassembledFile = disassembleData(data, size, false);
    return true;
}

/// 
/// \brief   Returns the filename if available, otherwise returns ""
/// \author  GrandChris
/// \date    2021-03-18
///
char const * elf_analysis_get_filename() {
    return disassembledFile.filename.c_str();
}

/// 
/// \brief   Returns the number of lines in the lines array
/// \author  GrandChris
/// \date    2021-03-18
///
unsigned int elf_analysis_get_lines_size() {
    return disassembledFile.lines.size();
}

/// 
/// \brief   Returns the program address of the line
/// \author  GrandChris
/// \date    2021-03-18
/// \param line Index in the lines array  
///
unsigned int elf_analysis_get_address(unsigned int line) {
    if(line >= disassembledFile.lines.size()) {
        return 0;
    }

    return disassembledFile.lines[line].address;
}

/// 
/// \brief   Returns the opcode as mnemonic with operaands
/// \author  GrandChris
/// \date    2021-03-18
/// \param line Index in the lines array  
///
char const * elf_analysis_get_opcode_description(unsigned int line) {
    if(line >= disassembledFile.lines.size()) {
        return "";
    }

    return disassembledFile.lines[line].opcode_description.c_str();
}

/// 
/// \brief   Returns program address of the destination of the branch instruction
/// \author  GrandChris
/// \date    2021-03-18
/// \param line Index in the lines array  
///
unsigned int elf_analysis_get_branch_destination(unsigned int line) {
    if(line >= disassembledFile.lines.size()) {
        return 0;
    }

    return disassembledFile.lines[line].branch_destination;
}

/// 
/// \brief   Returns the filename corresponding to that line
/// \author  GrandChris
/// \date    2021-03-18
/// \param line Index in the lines array  
///
char const * elf_analysis_get_line_filename(unsigned int line) {
    if(line >= disassembledFile.lines.size()) {
        return "";
    }

    return disassembledFile.lines[line].line.filename.c_str();
}

/// 
/// \brief   Returns the path (without filename) corresponding to that line
/// \author  GrandChris
/// \date    2021-03-18
/// \param line Index in the lines array  
///
char const * elf_analysis_get_line_path(unsigned int line) {
    if(line >= disassembledFile.lines.size()) {
        return "";
    }

    return disassembledFile.lines[line].line.path.c_str();
}

/// 
/// \brief   Returns the line number in the file
/// \author  GrandChris
/// \date    2021-03-18
/// \param line Index in the lines array  
///
unsigned int elf_analysis_get_line_line(unsigned int line) {
    if(line >= disassembledFile.lines.size()) {
        return 0;
    }

    return disassembledFile.lines[line].line.line;
}

/// 
/// \brief   Returns the column number in the file
/// \author  GrandChris
/// \date    2021-03-18
/// \param line Index in the lines array  
///
unsigned int elf_analysis_get_line_column(unsigned int line) {
    if(line >= disassembledFile.lines.size()) {
        return 0;
    }

    return disassembledFile.lines[line].line.column;
}

/// 
/// \brief   Returns if the instruction is the beginning of a new function
/// \author  GrandChris
/// \date    2021-03-18
/// \param line Index in the lines array  
///
unsigned int elf_analysis_get_line_isStartSequence(unsigned int line) {
    if(line >= disassembledFile.lines.size()) {
        return false;
    }

    return disassembledFile.lines[line].line.isStartSequence;
}

/// 
/// \brief   Returns the filename corresponding to the branch destination
/// \author  GrandChris
/// \date    2021-03-18
/// \param line Index in the lines array  
///
char const * elf_analysis_get_branch_destination_line_filename(unsigned int line) {
    if(line >= disassembledFile.lines.size()) {
        return "";
    }

    return disassembledFile.lines[line].branch_destination_line.filename.c_str();
}

/// 
/// \brief   Returns the path (without filename) corresponding to the branch destination
/// \author  GrandChris
/// \date    2021-03-18
/// \param line Index in the lines array  
///
char const * elf_analysis_get_branch_destination_line_path(unsigned int line) {
    if(line >= disassembledFile.lines.size()) {
        return "";
    }

    return disassembledFile.lines[line].branch_destination_line.path.c_str();
}

/// 
/// \brief   Returns the line number in the file of the branch destination
/// \author  GrandChris
/// \date    2021-03-18
/// \param line Index in the lines array  
///
unsigned int elf_analysis_get_branch_destination_line_line(unsigned int line) {
    if(line >= disassembledFile.lines.size()) {
        return 0;
    }

    return disassembledFile.lines[line].branch_destination_line.line;
}

/// 
/// \brief   Returns the column number in the file of the branch destination
/// \author  GrandChris
/// \date    2021-03-18
/// \param line Index in the lines array  
///
unsigned int elf_analysis_get_branch_destination_line_column(unsigned int line) {
    if(line >= disassembledFile.lines.size()) {
        return 0;
    }

    return disassembledFile.lines[line].branch_destination_line.column;
}

/// 
/// \brief   Returns if the instruction of the branch destination is the beginning of a new function
/// \author  GrandChris
/// \date    2021-03-18
/// \param line Index in the lines array  
///
unsigned int elf_analysis_get_branch_destination_line_isStartSequence(unsigned int line) {
    if(line >= disassembledFile.lines.size()) {
        return false;
    }

    return disassembledFile.lines[line].branch_destination_line.isStartSequence;
}

}
