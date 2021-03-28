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

#include "disassembler.h"

// #pragma GCC diagnostic push
// #pragma GCC diagnostic ignored "-Wall"
// #pragma GCC diagnostic ignored "-Wextra"
#include "elfio/elfio.hpp"
// #pragma GCC diagnostic pop

#include "dwarf/debug_line/header.h"
#include "dwarf/debug_line/state_machine.h"
#include <iomanip>
#include <iostream>
#include <string_view>
#include <unordered_map>
#include <algorithm>
#include "elf_analysis.h"

using namespace std;


#ifdef EMSCRIPTEN
int main2(int argc, char **argv)    // do not export this function if we use emscripten because we declared our own interface
#else
int main(int argc, char **argv)
#endif
{
    cout << "runnning main from " << argv[0] << endl;

    try
    {
        string filename = "";

        if (argc != 2)
        {
            cout << "usage: " << argv[0] << " "
                    << "elf-file" << endl;
            // filename = "./build/app/app";
            filename = "./test/NucleoProject.elf";
            // filename = "./test/ZEUS_STM32F765NG.elf";
            // return 2;
        }
        else
        {
            filename = argv[1];
        }

        DisassembledFile res = disassembleFile(filename);

        cout << "###########################################" << endl;
        cout << "File: " << res.filename << endl;
        cout << endl;

        for(auto & line : res.lines) {
            if(line.line.isStartSequence) {
                cout << endl;
            }

            cout << hex << "0x" << line.address << dec << " ";
            cout << left << setw(25) << line.opcode_description << " ";

            if(!line.line.filename.empty()) {
                cout << left << setw(25)
                << line.line.filename + ":" + to_string(line.line.line) + ":" + to_string(line.line.column) << " ";
            }
            
            if(line.branch_destination != 0) {
                
                cout << hex << "0x" << line.branch_destination << dec << " ";

                if(!line.branch_destination_line.filename.empty()) {
                    cout << line.branch_destination_line.filename + ":" + to_string(line.branch_destination_line.line) + ":" + to_string(line.branch_destination_line.column) << " ";
                }
            }

            if(line.line.isStartSequence) {
                cout << "   BEGIN";
            }

            cout << endl;
        }

        cout << "finished" << endl;
    }
    catch (std::exception const &e)
    {
        cout << e.what() << endl;
        return 1;
    }

    return 0;
}
