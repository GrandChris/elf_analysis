

const fs = require('fs')

async function create_elf_analysis(elf_analysis_path) {
    var factory = require(elf_analysis_path);

    var instance = await factory();
    
    var res = {
        instance: instance,
        analyse_data: instance.cwrap('elf_analysis_analyse_data', 'number', ['number', 'number']),
        get_filename: instance.cwrap('elf_analysis_get_filename', 'string'),
        get_lines_size: instance.cwrap('elf_analysis_get_lines_size', 'number'),

        get_address: instance.cwrap('elf_analysis_get_address', 'number', ['number']),
        get_opcode_description: instance.cwrap('elf_analysis_get_opcode_description', 'string', ['number']),
        get_branch_destination: instance.cwrap('elf_analysis_get_branch_destination', 'number', ['number']),

        get_line_filename: instance.cwrap('elf_analysis_get_line_filename', 'string', ['number']),
        get_line_path: instance.cwrap('elf_analysis_get_line_path', 'string', ['number']),
        get_line_line: instance.cwrap('elf_analysis_get_line_line', 'number', ['number']),
        get_line_column: instance.cwrap('elf_analysis_get_line_column', 'number', ['number']),
        get_line_isStartSequence: instance.cwrap('elf_analysis_get_line_isStartSequence', 'number', ['number']),

        get_branch_destination_line_filename: instance.cwrap('elf_analysis_get_branch_destination_line_filename', 'string', ['number']),
        get_branch_destination_line_path: instance.cwrap('elf_analysis_get_branch_destination_line_path', 'string', ['number']),
        get_branch_destination_line_line: instance.cwrap('elf_analysis_get_branch_destination_line_line', 'number', ['number']),
        get_branch_destination_line_column: instance.cwrap('elf_analysis_get_branch_destination_line_column', 'number', ['number']),
        get_branch_destination_line_isStartSequence: instance.cwrap('elf_analysis_get_branch_destination_line_isStartSequence', 'number', ['number'])
    }   

    return res;
}


async function main() {
    try {
        var elf_analysis = await create_elf_analysis('./elf_analysis.js');
    }
    catch {
        var elf_analysis = await create_elf_analysis('../build_emcc/app/elf_analysis.js');
    }
    
    const file = './test/NucleoProject.elf.elf';

    try {
        const data = fs.readFileSync(file, null);

        console.log("Number of Lines: ", elf_analysis.get_lines_size());    // just to check if it is working

        // Allocate some space in the heap for the data (making sure to use the appropriate memory size of the elements)
        buffer = instance._malloc(data.length)
        // Assign the data to the heap - Keep in mind bytes per element
        instance.HEAPU8.set(data, buffer);

        var ret = elf_analysis.analyse_data(buffer, data.length);
        console.log("Number of Lines: ", elf_analysis.get_lines_size());
    } catch (err) {
        console.error(err)
    }
}

main();
