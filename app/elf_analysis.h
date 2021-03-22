
#include <string>
#include <vector>

#pragma once


struct Line {
    std::string filename;
    std::string path;
    uint32_t line;
    uint32_t column;
    bool isEndSequence;
};

struct DisassembledLine {
    uint64_t address;
    std::string opcode_description;
    uint64_t branch_destination;
    Line branch_destination_line;
    Line line;
};

struct DisassembledFile {
    std::string filename;
    std::vector<DisassembledLine> lines;
};


DisassembledFile disassembleFile(std::string const & filename, bool print_debug_info = true);