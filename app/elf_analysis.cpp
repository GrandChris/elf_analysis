

#include "elf_analysis.h"
#include "disassembler.h"

// #pragma GCC diagnostic push
// #pragma GCC diagnostic ignored "-Wall"
// #pragma GCC diagnostic ignored "-Wextra"
#include "elfio/elfio.hpp"
// #pragma GCC diagnostic pop

#include "dwarf/debug_line/header.h"
#include "dwarf/debug_line/state_machine.h"
#include <chrono>
#include <filesystem>
#include <unordered_map>
#include <sstream>

using namespace std;

DisassembledFile disassembleFile(string const & filename, bool print_debug_info) 
{
    std::ifstream stream;
        stream.open( filename.c_str(), std::ios::in | std::ios::binary );
        if ( !stream ) {
            return {};
        }

    return disassembleInput(stream, print_debug_info);  
}

DisassembledFile disassembleData(uint8_t const data[], size_t const length, bool print_debug_info) 
{
    string datastr(reinterpret_cast<char const *>(data), length);
    istringstream in(datastr);

    return disassembleInput(in, print_debug_info);
}


DisassembledFile disassembleInput(std::istream & in, bool print_debug_info) 
{
    auto start = chrono::steady_clock::now();

    auto lbd_stop_time = [&]() {
        auto end = chrono::steady_clock::now();
        cout << "Duration : "
            << chrono::duration_cast<chrono::milliseconds>(end - start).count()
            << " ms" << endl;
        start = end;
    };

    lbd_stop_time();
    cout << "### reading file ###" << endl;

    DisassembledFile res = {};
    res.filename = "";

    // Create elfio reader
    ELFIO::elfio reader; 
    if ( !reader.load( in ) ) {      
            std::cout << "Can't find or process ELF file " << std::endl;
            // std::cout << "Current path: " << std::filesystem::current_path() << std::endl;
            // std::cout << "Files in the directory: " << endl;

            // string path = std::filesystem::current_path();

            // for (const auto & file : std::filesystem::directory_iterator(path))
            //     cout << file.path() << endl;

            // std::cout << "Files in working: " << endl;

            // string path2 = string(std::filesystem::current_path()) + "/working";

            // for (const auto & file : std::filesystem::directory_iterator(path2))
            //     cout << file.path() << endl;
    }

    if(print_debug_info) {
        // Print ELF file properties
        std::cout << "ELF file class    : ";
        if ( reader.get_class() == ELFCLASS32 )std::cout << "ELF32" << std::endl;
        else {
            std::cout << "ELF64" << std::endl;
        }
        std::cout << "ELF file encoding : ";
        if ( reader.get_encoding() == ELFDATA2LSB ) {
            std::cout << "Little endian" << std::endl;
        }
        else {
            std::cout << "Big endian" << std::endl;
        }
        std::cout << "Machine: " << reader.get_machine() << std::endl;
    }

    // read sections
    std::span<uint8_t const> debug_line;
    std::span<uint8_t const> text;
    uint64_t text_address = 0;

    // Print ELF file sections info
    ELFIO::Elf_Half sec_num = reader.sections.size();
    if(print_debug_info) {
        std::cout << "Number of sections: " << sec_num << std::endl;
    }
    
    for ( int i = 0; i < sec_num; ++i ) {
        const ELFIO::section* psec = reader.sections[i];

        if(print_debug_info) {
            std::cout << "  [" << i << "] "<< psec->get_name()<< "\t"<< psec->get_size() << " address: " << hex << psec->get_address() << dec << std::endl;
        }

        if(psec->get_name() == ".debug_line") {
            debug_line =  std::span<uint8_t const>(reinterpret_cast<uint8_t const *>(reader.sections[i]->get_data()), static_cast<size_t>(psec->get_size()));
        }
        else if(psec->get_name() == ".text") {
            text =  std::span<uint8_t const>(reinterpret_cast<uint8_t const *>(reader.sections[i]->get_data()), static_cast<size_t>(psec->get_size()));
            text_address = psec->get_address();
        }
    }

    // read debug_line headers
    auto const debug_line_headers = dwarf::debug_line::Header::read(debug_line);

    lbd_stop_time();
    cout << "### decode debug_line section ###" << endl;
    // decode debug_line
    unordered_map<uint64_t, Line> line_map;
    std::vector<uint64_t> end_sequence_map;

    for(auto const & header : debug_line_headers) 
    {
        auto const lineTable = dwarf::debug_line::decode_data(header);
        // cout << "line table size: " << lineTable.size() << endl;;

        for(auto const & elem : lineTable) {
            if(!elem.end_sequence) {
                auto const address = elem.address;
                auto const & fileName = header.file_names[elem.file - 1];
                Line lineMapData = {
                    .filename = std::string(fileName.name),
                    .path = std::string(header.include_directories[fileName.include_directories_index - 1]),
                    .line = elem.line,
                    .column = elem.column
                };

                line_map.insert({address, lineMapData}); 
            }   
            else {
                end_sequence_map.push_back(elem.address);
            }    
        }

        // debug plot
        // for(size_t i = 0; i < lineTable.size(); ++i) {
        //     auto const & file_name = header.file_names[lineTable[i].file - 1];

        //     cout << i << " " << hex << lineTable[i].address << dec << " " 
        //         <<  file_name.name << ":" << lineTable[i].line << ":" << lineTable[i].column;
        //     if(lineTable[i].end_sequence) {
        //         cout << " END" << endl;
        //     }
        //     cout << endl;
        // }
    }
    std::sort(end_sequence_map.begin(), end_sequence_map.end());

    lbd_stop_time();
    cout << "### dissassemble  text section ###" << endl;
    // Dissassemble file
    if(reader.get_machine() == EM_ARM) {
        disassembler dis (CS_ARCH_ARM, CS_MODE_THUMB);

        auto code = dis(text, text_address);
        cout << "instruction count: " << code.size() << endl;

        for(auto & elem : code) {
            
            uint32_t const sourceAddress = static_cast<uint32_t>(elem.address);
            uint32_t targetAddress = 0;

            if(elem.id == ARM_INS_BL) {
                if(elem.detail->arm.op_count == 1) {
                    targetAddress = elem.detail->arm.operands[0].imm;
                }
            }

            DisassembledLine disassembledLine = {};
            disassembledLine.address = sourceAddress;
            disassembledLine.branch_destination = targetAddress;
            disassembledLine.opcode_description =  string(elem.mnemonic) + " " + string(elem.op_str); // + " " + to_string(elem.id);

            res.lines.push_back(disassembledLine);
        }
    }
    else if(reader.get_machine() == EM_X86_64) {
        disassembler dis (CS_ARCH_X86, CS_MODE_64);

        auto code = dis(text, text_address);
        cout << "instruction count: " << code.size() << endl;

        for(auto & elem : code) {
            
            uint64_t const sourceAddress = static_cast<uint64_t>(elem.address);
            uint64_t targetAddress = 0;

            if(elem.id == X86_INS_CALL) {
                if(elem.detail->x86.op_count == 1) {
                    targetAddress = elem.detail->x86.operands[0].imm;
                }
            }

            DisassembledLine disassembledLine = {};
            disassembledLine.address = sourceAddress;
            disassembledLine.branch_destination = targetAddress;
            disassembledLine.opcode_description =  string(elem.mnemonic) + " " + string(elem.op_str); // + " " + to_string(elem.id);

            res.lines.push_back(disassembledLine);
        }
    }
    else {
        cout << "Machine not found" << endl;
    }

    lbd_stop_time();
    cout << "### mapping line addressses ###" << endl;

    auto next_end_sequence = [](auto iter, auto iter_end, uint64_t address) {
        while(iter != iter_end && *iter < address) {
            ++iter;
        }

        return iter;
    };

    //find lines for addresses
    auto iter_end_sequence = end_sequence_map.begin();
    Line * previous_elem = nullptr;
    uint64_t previous_address = 0;
    for(auto & elem : res.lines) {
        auto iter = line_map.find(elem.address);
        if(iter != line_map.end()) {
            elem.line = iter->second;

            if(iter_end_sequence != end_sequence_map.end() && *iter_end_sequence < elem.address) {
                elem.line.isEndSequence = true;
                iter_end_sequence = next_end_sequence(iter_end_sequence, end_sequence_map.end(), elem.address);
            }

            previous_elem = &iter->second;
            previous_address = elem.address;
        }
        else if(previous_elem != nullptr && elem.address - previous_address < 64) {
             elem.line = *previous_elem;
        }

        if(elem.branch_destination != 0) {
            auto iter_branch = line_map.find(elem.branch_destination);
            if(iter_branch != line_map.end()) {
                elem.branch_destination_line = iter_branch->second;
            }
        }
    }

    // size_t last_empty = 0;
    // for(size_t i = 0; i < res.lines.size(); ++i) {
    //     auto & elem = res.lines[i];
    //     auto iter = line_map.find(elem.address);

    //     if(iter != line_map.end()) {
    //         elem.line = iter->second;
    //         if(last_empty != 0) {
    //             for(size_t j = last_empty; j < i; ++j){
    //                 auto & previousLine = res.lines[j].line;
    //                 previousLine = iter->second;
    //                 previousLine.isEndSequence = false;
    //                 last_empty = 0;
    //             }
    //         }

    //     }
    //     else if(last_empty == 0) {
    //         last_empty = i;
    //     }

    //     if(elem.branch_destination != 0) {
    //         auto & branch_destination_line = elem.branch_destination_line;
    //         auto iter_branch = line_map.find(elem.branch_destination);
    //         if(iter_branch != line_map.end()) {
    //             branch_destination_line = iter_branch->second;
    //         }
    //     }
    // }

    lbd_stop_time();
    return res;
}
