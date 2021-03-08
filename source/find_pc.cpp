
#include "find_pc.h"

// #include "elf/elf++.hh"


using namespace std;

bool find_pc(const dwarf::die &d, dwarf::taddr pc, vector<dwarf::die> *stack)
{
        using namespace dwarf;

        // Scan children first to find most specific DIE
        bool found = false;
        for (auto &child : d) {
                if ((found = find_pc(child, pc, stack)))
                        break;
        }
        switch (d.tag) {
        case DW_TAG::subprogram:
        case DW_TAG::inlined_subroutine:
                try {
                        if (found || die_pc_range(d).contains(pc)) {
                                found = true;
                                stack->push_back(d);
                        }
                } catch (out_of_range &e) {
                } catch (value_type_mismatch &e) {
                }
                break;
        default:
                break;
        }
        return found;
}

// void dump_die(const dwarf::die &node)
// {
//         printf("<%" PRIx64 "> %s\n",
//                node.get_section_offset(),
//                to_string(node.tag).c_str());
//         for (auto &attr : node.attributes())
//                 printf("      %s %s\n",
//                        to_string(attr.first).c_str(),
//                        to_string(attr.second).c_str());
// }

string find_address(dwarf::dwarf const &dw, uint32_t const address)
{
    string res;

    dwarf::taddr pc = address;

    // Find the CU containing pc
    // XXX Use .debug_aranges
    for (auto &cu : dw.compilation_units())
    {
        // if (die_pc_range(cu.root()).contains(pc))
        {
            // Map PC to a line
            auto &lt = cu.get_line_table();
            auto it = lt.find_address(pc);
            if (it != lt.end()) {
                res = it->get_description();
                break;
            }
            
                

            // Map PC to an object
            // XXX Index/helper/something for looking up PCs
            // XXX DW_AT_specification and DW_AT_abstract_origin
            // vector<dwarf::die> stack;
            // if (find_pc(cu.root(), pc, &stack)) {
            //         bool first = true;
            //         for (auto &d : stack) {
            //                 if (!first)
            //                         printf("\nInlined in:\n");
            //                 first = false;
            //                 dump_die(d);
            //         }
            // }
            
        }
    }

    return res;
}