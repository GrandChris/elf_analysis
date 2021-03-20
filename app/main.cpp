#ifdef EMSCRIPTEN
// #ifndef NODERAWFS
//     // mount the current folder as a NODEFS instance
//     // inside of emscripten
//     #include <emscripten.h>

//     bool initFileSystem()
//     {
//         EM_ASM(
//             FS.mkdir('/working');
//             FS.mount(NODEFS, {root : './'}, '/working'););
//         return true;
//     }
//     bool isFileSystemInitialized = initFileSystem();

// #endif
#endif

#include "arm_thumb_bl.h"
#include "disassembler.h"
#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"
#include "elf_file_loader.h"
#include "find_pc.h"
// #include "line_table.h"
#include "dwarf/debug_line/header.h"
#include "dwarf/debug_line/state_machine.h"
#include <iostream>
#include <string_view>

using namespace std;

void print_line_table(const dwarf::line_table &lt)
    {
        for (auto const &line : lt)
        {
            if (line.end_sequence)
            {
                cout << endl;
            }
            else
            {
                cout << line.file->path << " " << line.line << " " << line.address << endl;
            }
        }
}

struct file_table_entry {
    uint32_t address;
    string line;
};

void add_lines(std::vector<file_table_entry> & table, const dwarf::line_table &lt) {

    for(auto const & line : lt)
    {
        if(line.end_sequence) {
            //cout << endl;
        }
        else {
            uint32_t address = line.address;
            string line_str = line.file->path + ":" + to_string(line.line) + ":" + to_string(line.column);
            table.push_back({address, line_str});
        }
    }


}


void main_print() {
    cout << "Hello World!" << endl;
}

int main(int argc, char **argv)
{
    main_print();

    try
    {
        string filename = "";

        if (argc != 2)
        {
            cout << "usage: " << argv[0] << " "
                    << "elf-file" << endl;
            // filename = "./build/app/app";
            // filename = "./test/NucleoProject.elf";
            filename = "./test/ZEUS_STM32F765NG.elf";
            // return 2;
        }
        else
        {
            filename = argv[1];
        }

        // Load file
        auto const loader = std::make_shared<elf_file_loader>(filename);
        elf::elf ef(loader);

        // Print elf sections
        auto const &hdr = ef.get_hdr();

        cout << "elf entry: " << hdr.entry << endl;
        cout << "machine: " << hdr.machine << endl;

        for (auto const &sec : ef.sections())
        {
            auto const &hdr = sec.get_hdr();
            cout << "section " << sec.get_name() << " " << hex << hdr.addr
                    << " " << dec <<  hdr.offset << " " << hdr.size << endl;
        }
        cout << endl;

        // // Print line table
        // auto const elf_loader = dwarf::elf::create_loader(ef);
        // dwarf::dwarf dw(elf_loader);

        // std::vector<file_table_entry> line_table;

        // for(auto cu : dw.compilation_units()) {

        //     uint32_t const offset = cu.get_section_offset();

        //     cout << offset << endl;

        //     add_lines(line_table, cu.get_line_table());

        //     // print_line_table(cu.get_line_table());
        // }

        // std::sort(line_table.begin(), line_table.end(),
        //     [](file_table_entry const & left, file_table_entry const & right) {
        //         return left.address < right.address;
        //     }
        // );

        cout << endl;
        auto const & comment = ef.get_section(".comment");
        char const * comment_text = static_cast<char const *>(comment.data());
        cout << comment_text << endl;
        cout << endl;

        auto const & debug_line = ef.get_section(".debug_line");
        size_t const debug_line_size = debug_line.size();
        uint8_t const * debug_line_data = static_cast<uint8_t const *>(debug_line.data());
        // cout << debug_line_data << endl;

        // auto const lineNumberProgramHeader = ReadLineNumberProgramHeader(debug_line_data);
        // create_line_table(debug_line_data);
        auto const debug_line_headers = dwarf::debug_line::Header::read(std::span(debug_line_data, debug_line_size));
        // size_t const debug_line_headers_size = debug_line_headers.size();


        for(auto const & header : debug_line_headers) {
            // header.print(cout);

            auto const lineTable = dwarf::debug_line::decode_data(header);
            cout << "line table size: " << lineTable.size() << endl;;

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


        


        // read all bl instructions
        cout << endl;
        auto const & text = ef.get_section(".text");
        cout << text.get_name() << endl;
        cout << text.size() << endl;

        auto const & text_hdr = text.get_hdr();

        cout << endl;
        cout << text_hdr.addr << endl;
        cout << text_hdr.addralign << endl;
        cout << text_hdr.entsize << endl;
        cout << to_string(text_hdr.flags) << endl;
        cout << text_hdr.info << endl;
        cout << text_hdr.link << endl;
        cout << text_hdr.name << endl;
        cout << text_hdr.offset << endl;
        // cout << to_string(text_hdr.order) << endl;
        cout << text_hdr.size << endl;
        cout << to_string(text_hdr.type) << endl;

        


        struct branch {
            uint32_t source_address;
            string source_line;
            uint32_t target_address;
            string target_line;
        };

        std::vector<branch> branches;


        // uint16_t const * data = static_cast<uint16_t const *>(text.data());

        // uint32_t pc = text_hdr.addr;
        // for(size_t i = 0; i < text.size() / sizeof(uint16_t); ++i) {
        //     uint16_t const inst1 = data[i];

        //     if(arm_thumb_bl::isValid(inst1) && (i+1) < (text.size() / sizeof(uint16_t))) {
        //         uint16_t const inst2 = data[i+1];

        //         if(arm_thumb_bl::isValid(inst1, inst2))
        //         {
        //             uint32_t const target_address = arm_thumb_bl(inst1, inst2, pc).getTargetAddress();

        //             branches.push_back({.source_address = pc, .target_address = target_address});

        //             pc += sizeof(uint16_t);
        //             ++i;
        //         }
        //     }

        //     pc += sizeof(uint16_t);
        // }

        uint8_t const * data2 = static_cast<uint8_t const *>(text.data());
        disassembler dis(CS_ARCH_ARM, CS_MODE_THUMB);

        auto const data2_span = std::span(data2, text.size());
        auto code = dis(data2_span, text.get_hdr().addr);
        cout << "instruction count: " << code.size() << endl;

        for(auto & elem : code) {

            if(elem.id == ARM_INS_BL) {
                uint32_t const sourceAddress = static_cast<uint32_t>(elem.address);
                uint32_t targetAddress = 0;
                if(elem.detail->arm.op_count == 1) {
                    targetAddress = elem.detail->arm.operands[0].imm;
                }

                branches.push_back({.source_address = sourceAddress, .target_address = targetAddress});
            }

            
//             cout << hex << elem.address << " ";
            
//             for(size_t i = 0; i < elem.size; ++i) {
//                 cout << hex << static_cast<uint32_t>(elem.bytes[i]);
//             }
            

//             cout << " " <<  elem.mnemonic << " " << elem.op_str << " " << dec << elem.id  << endl;

//             if(elem.id != 0) {
// cs_detail *detail = elem.detail;

//             for(size_t i = 0; i < detail->arm.op_count; ++i) {
//                 cs_arm_op & op = detail->arm.operands[i];
//                 switch(op.type) {
//                 case ARM_OP_INVALID: ///< = CS_OP_INVALID (Uninitialized).
//                     cout << " invalid";
//                     break;
//                 case ARM_OP_REG: ///< = CS_OP_REG (Register operand).
//                     cout << " reg: " << op.reg;
//                     break;
//                 case ARM_OP_IMM: ///< = CS_OP_IMM (Immediate operand).
//                     cout << " imm: " << op.imm;
//                     break;
//                 case ARM_OP_MEM: ///< = CS_OP_MEM (Memory operand).
//                     cout << " mem: ";
//                     break;
//                 case ARM_OP_FP:  ///< = CS_OP_FP (Floating-Point operand).
//                     cout << " fp: " << op.fp;
//                     break;
//                 case ARM_OP_CIMM: ///< C-Immediate (coprocessor registers)
//                     cout << " cimm: " << op.imm;
//                     break;
//                 case ARM_OP_PIMM: ///< P-Immediate (coprocessor registers)
//                     cout << " pimm: " << op.imm;
//                     break;
//                 case ARM_OP_SETEND:	///< operand for SETEND instruction
//                     cout << " setend: " << op.setend;
//                     break;
//                 case ARM_OP_SYSREG:	///< MSR/MRS special register operand
//                     cout << " sysreg: ";
//                     break;
//                 }
//                 cout << endl;

            // }

            // for (size_t i = 0; i < detail->regs_read_count; i++) {
            //     cout << detail->regs_read[i] << " ";
			// }
            // cout << endl;
            // }
            

        }

        cout << branches.size() << endl;


        // for(auto & elem: branches) {
        //     auto  iter = std::lower_bound(line_table.cbegin(), line_table.cend(), 
        //         elem.source_address, 
        //         [](auto const & left, auto const & right) {
        //             return left.address < right;
        //         });

        //     if(iter != line_table.cend()) {
        //         elem.source_line = (--iter)->line;
        //     }   

        //     auto  iter2 = std::lower_bound(line_table.cbegin(), line_table.cend(), 
        //         elem.target_address, 
        //         [](auto const & left, auto const & right) {
        //             return left.address < right;
        //         });

        //     if(iter2 != line_table.cend()) {
        //         elem.target_line = iter2->line;
        //     } 
        // }


        // for(auto & elem: branches) {
        //    elem.source_line = find_address(dw, elem.source_address);
        //    elem.target_line = find_address(dw, elem.target_address);
        // }

        


        // for(auto & elem : branches) {
        //     cout << hex << elem.source_address << " " << elem.target_address << endl;;
        //     cout << elem.source_line << endl;
        //     cout << elem.target_line << endl;
        //     cout << endl;
        // }

        cout << "finished" << endl;
    }
    catch (std::exception const &e)
    {
        cout << e.what() << endl;
        return 1;
    }

    cout << "finished more" << endl;
    return 0;
}

// #include "elf/elf++.hh"
// #include "dwarf/dwarf++.hh"

// #include <errno.h>
// #include <fcntl.h>
// #include <inttypes.h>

// using namespace std;

// void dump_tree(const dwarf::die &node, int depth = 0)
// {
//     printf("%*.s<%" PRIx64 "> %s\n", depth, "",
//            node.get_section_offset(),
//            to_string(node.tag).c_str());
//     for (auto &attr : node.attributes())
//         printf("%*.s      %s %s\n", depth, "",
//                to_string(attr.first).c_str(),
//                to_string(attr.second).c_str());
//     for (auto &child : node)
//         dump_tree(child, depth + 1);
// }

// int main(int argc, char **argv)
// {
//     if (argc != 2)
//     {
//         fprintf(stderr, "usage: %s elf-file\n", argv[0]);
//         return 2;
//     }

//     int fd = open(argv[1], O_RDONLY);
//     if (fd < 0)
//     {
//         fprintf(stderr, "%s: %s\n", argv[1], strerror(errno));
//         return 1;
//     }

//     elf::elf ef(elf::create_mmap_loader(fd));
//     dwarf::dwarf dw_very_spezial(dwarf::elf::create_loader(ef));

//     for (auto cu : dw_very_spezial.compilation_units())
//     {
//         printf("--- <%" PRIx64 ">\n", cu.get_section_offset());
//         dump_tree(cu.root());
//     }

//     return 0;
// }










// /*
//  * Copyright 2013 The Emscripten Authors.  All rights reserved.
//  * Emscripten is available under two separate licenses, the MIT license and the
//  * University of Illinois/NCSA Open Source License.  Both these licenses can be
//  * found in the LICENSE file.
//  */

// #include <assert.h>
// #include <stdio.h>
// #include <string.h>


// #ifdef NODERAWFS
// #define CWD ""
// #else
// #define CWD "/working/"
// #endif

// int main()
// {
//     FILE *file;
//     int res;
//     char buffer[512];

//     // write something locally with node
//     EM_ASM(
//         var fs = require('fs');
//         fs.writeFileSync('foobar.txt', 'yeehaw'););

// #ifndef NODERAWFS
//     // mount the current folder as a NODEFS instance
//     // inside of emscripten
//     #include <emscripten.h>

//     bool initFileSystem()
//     {
//         EM_ASM(
//             FS.mkdir('/working');
//             FS.mount(NODEFS, {root : '.'}, '/working'););
//         return true;
//     }
//     bool isFileSystemInitialized = initFileSystem();

// #endif

//     // read and validate the contents of the file
//     file = fopen(CWD "foobar.txt", "r");
//     assert(file);
//     res = fread(buffer, sizeof(char), 6, file);
//     assert(res == 6);
//     fclose(file);

//     assert(!strcmp(buffer, "yeehaw"));

//     // write out something new
//     file = fopen(CWD "foobar.txt", "w");
//     assert(file);
//     res = fwrite("cheez", sizeof(char), 5, file);
//     assert(res == 5);
//     fclose(file);

//     // validate the changes were persisted to the underlying fs
//     EM_ASM(
//         var fs = require('fs');
//         var contents = fs.readFileSync('foobar.txt', {encoding : 'utf8'});
//         assert(contents == = 'cheez'););

//     puts("success");

//     return 0;
// }










// #include "elf/elf++.hh"
// #include "dwarf/dwarf++.hh"

// #include <errno.h>
// #include <fcntl.h>
// #include <string>
// #include <inttypes.h>
// #include <iostream>

// using namespace std;

// void
// usage(const char *cmd) 
// {
//         fprintf(stderr, "usage: %s elf-file pc\n", cmd);
//         exit(2);
// }

// bool
// find_pc(const dwarf::die &d, dwarf::taddr pc, vector<dwarf::die> *stack)
// {
//         using namespace dwarf;

//         // Scan children first to find most specific DIE
//         bool found = false;
//         for (auto &child : d) {
//                 if ((found = find_pc(child, pc, stack)))
//                         break;
//         }
//         switch (d.tag) {
//         case DW_TAG::subprogram:
//         case DW_TAG::inlined_subroutine:
//                 try {
//                         if (found || die_pc_range(d).contains(pc)) {
//                                 found = true;
//                                 stack->push_back(d);
//                         }
//                 } catch (out_of_range &e) {
//                 } catch (value_type_mismatch &e) {
//                 }
//                 break;
//         default:
//                 break;
//         }
//         return found;
// }

// void
// dump_die(const dwarf::die &node)
// {
//         printf("<%" PRIx64 "> %s\n",
//                node.get_section_offset(),
//                to_string(node.tag).c_str());
//         for (auto &attr : node.attributes())
//                 printf("      %s %s\n",
//                        to_string(attr.first).c_str(),
//                        to_string(attr.second).c_str());
// }

// int
// main(int argc, char **argv)
// {
//         if (argc != 3)
//                 usage(argv[0]);


//         dwarf::taddr pc;
//         try {
//                 pc = stoll(argv[2], nullptr, 0);
//                 cout << pc << endl;
                
//         } catch (invalid_argument &e) {
//                 usage(argv[0]);
//         } catch (out_of_range &e) {
//                 usage(argv[0]);
//         }

//         int fd = open(argv[1], O_RDONLY);
//         if (fd < 0) {
//                 fprintf(stderr, "%s: %s\n", argv[1], strerror(errno));
//                 return 1;
//         }

//         elf::elf ef(elf::create_mmap_loader(fd));
//         dwarf::dwarf dw(dwarf::elf::create_loader(ef));

//         // Find the CU containing pc
//         // XXX Use .debug_aranges
//         for (auto &cu : dw.compilation_units()) {
//                 if (die_pc_range(cu.root()).contains(pc)) {
//                         // Map PC to a line
//                         auto &lt = cu.get_line_table();
//                         auto it = lt.find_address(pc);
//                         if (it == lt.end())
//                                 printf("UNKNOWN\n");
//                         else
//                                 printf("%s\n",
//                                        it->get_description().c_str());

//                         // Map PC to an object
//                         // XXX Index/helper/something for looking up PCs
//                         // XXX DW_AT_specification and DW_AT_abstract_origin
//                         vector<dwarf::die> stack;
//                         if (find_pc(cu.root(), pc, &stack)) {
//                                 bool first = true;
//                                 for (auto &d : stack) {
//                                         if (!first)
//                                                 printf("\nInlined in:\n");
//                                         first = false;
//                                         dump_die(d);
//                                 }
//                         }
//                         break;
//                 }
//         }

//         return 0;
// }
